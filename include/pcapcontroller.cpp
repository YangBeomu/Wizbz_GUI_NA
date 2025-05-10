#include "pcapcontroller.h"

using namespace std;

PcapController::PcapController(QObject *parent)
    : QObject{parent}
{
    InitInterfaceInfo();
}

PcapController::~PcapController() {
    if(pcap_ != NULL)
        pcap_close(pcap_);
}

void PcapController::OpenThread() {
    hPThread_ = std::thread(&PcapController::RecvPacketThreadFunc, this);
}

void PcapController::play() {
    if(status_ == STATUS_PAUSE) {
        status_ = STATUS_PLAY;
        cv_.notify_all();
    }

    unique_lock<mutex> t(this->mtx_);
    status_ = STATUS_PLAY;
}

void PcapController::pause() {
    unique_lock<mutex> t(this->mtx_);
    status_ = STATUS_PAUSE;
}

void PcapController::end() {
    unique_lock<mutex> t(this->mtx_);
    status_ = STATUS_END;
}

void PcapController::WarningMessage(const QString msg) {
    cout<<"---PcapController---"<<endl;
    cout<<"WarningMessage : "<<msg.toStdString()<<endl;
}

bool PcapController::OpenPcap(string interface, int timeout) {
    try {
        if(pcap_ != nullptr) {
            pcap_close(pcap_);
            pcap_ = nullptr;
        }

        char errBuf[PCAP_ERRBUF_SIZE]{};

        pcap_ = pcap_open_live(interface.c_str(), BUFSIZ, 1, timeout, errBuf);
        if(pcap_ == NULL) throw runtime_error("Failed to open pcap : " + string(errBuf));
    }catch(const exception& e) {
        cerr<<"OpenPcap : "<<e.what()<<endl;
        return false;
    }

    return true;
}

void PcapController::InitInterfaceInfo() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    try {
        if(sock < 0)
            throw runtime_error("Failed to creat socket");

        ifconf ifConfig{};
        char buffer[1024];

        ifConfig.ifc_len = sizeof(buffer);
        ifConfig.ifc_buf = buffer;

        if(ioctl(sock, SIOCGIFCONF, &ifConfig) == -1)
            throw runtime_error("Failed to call ioctl with SIOCGIFCONF");

        int interfaceCnt = ifConfig.ifc_len / sizeof(ifreq);

        InterfaceInfo info{};


        if(interfaceCnt > 0) {
            for(int idx = 0; idx < interfaceCnt; idx++) {
                //interface name
                info.interfaceName_ = ifConfig.ifc_ifcu.ifcu_req[idx].ifr_ifrn.ifrn_name;
                if(ioctl(sock, SIOCGIFHWADDR, &ifConfig.ifc_ifcu.ifcu_req[idx]) == -1)
                    throw runtime_error("Failed to call ioctl with SIOCGIFHWADDR");
                //mac-address
                info.mac_ = reinterpret_cast<u_char*>(ifConfig.ifc_ifcu.ifcu_req[idx].ifr_ifru.ifru_hwaddr.sa_data);

                if(ioctl(sock, SIOCGIFADDR, &ifConfig.ifc_ifcu.ifcu_req[idx]) == -1)
                    throw runtime_error("Failed to call ioctl with SIOCGIFADDR");

                memcpy(&info.ip_,
                       ifConfig.ifc_ifcu.ifcu_req[idx].ifr_ifru.ifru_addr.sa_data, sizeof(Ip));

                 if (ioctl(sock, SIOCGIFNETMASK, &ifConfig.ifc_ifcu.ifcu_req[idx]) == -1)
                    throw runtime_error("Failed to call ioctl with SIOCGIFNETMASK");

                 memcpy(&info.netMask_,
                        ifConfig.ifc_ifcu.ifcu_req[idx].ifr_ifru.ifru_addr.sa_data, sizeof(Ip));

                interfaceInfos_.push_back(info);
            }
        }


    }
    catch(const exception& e) {
        cerr<<"[InitIntefaceInfo] "<<e.what() <<endl;
        cerr<<"Error : "<< errno <<" (" << strerror(errno)<<")"<<endl;
    }


    close(sock);
}

bool PcapController::ReadPacket() {
    if(pcap_ == nullptr) return false;

    if(pcap_next_ex(pcap_, &recvData_.header, (const uchar**)&recvData_.buf) != 1)
        return false;



    return true;
}

bool PcapController::SendPacket(uint8_t* pPacket, uint32_t size) {
    try {
    if(pcap_ == nullptr) throw runtime_error("Failed to find pcap opended");

    if(pcap_sendpacket(pcap_, reinterpret_cast<u_char*>(pPacket), size) == -1)
        throw runtime_error("Failed to send packet : " + string(pcap_geterr(pcap_)));
    }catch(const exception& e) {
        cerr<<"Failed to send packet : "<<e.what()<<endl;
        return false;
    }

    return true;
}

bool PcapController::SetPcapFilter(const string filterExpression) {
    bpf_program bp{};

    if(pcap_ == nullptr) {
        cout<<"pcap has not been initialized."<<endl;
        return false;
    }

    try {
        if(pcap_compile(pcap_, &bp, filterExpression.c_str(), 1, cInterfaceInfo_.netMask_) == PCAP_ERROR) throw runtime_error("Failed to call pcap_compile");
        if(pcap_setfilter(pcap_, &bp) == PCAP_ERROR) throw runtime_error("Failed to call pcap_setfilter");
    }catch (const exception& e) {
        cerr<<"[SetPcapFilter] "<< e.what()<<endl;
        cerr<< "ERROR : "<<pcap_geterr(pcap_) << endl;
        return false;
    }

    return true;
}

PcapController::Packet PcapController::GetPacket(const uint16_t etherType, const string ip, const IpHdr::PROTOCOL_ID_TYPE type, const uint16_t port) {
    Packet data{};

    //arp header size : 28
    if(recvData_.header->caplen < sizeof(EthHdr) + sizeof(IpHdr)) return data;

    EthHdr* etherHeader = reinterpret_cast<EthHdr*>(recvData_.buf);

    if(etherHeader->type() != etherType) return {};

    switch(etherHeader->type()) {
    case EthHdr::Arp: {
        data = recvData_;
        break;
    }
    case EthHdr::Ip4: {
        IpHdr* ipHeader = reinterpret_cast<IpHdr*>(recvData_.buf + sizeof(EthHdr));
        //Ip struct compare

        if(ipHeader->sip().compare(ip) == 0 || ipHeader->dip().compare(ip) == 0) {
            if(ipHeader->protocolId_ != type) return {};

            switch(ipHeader->protocolId_) {
            case IpHdr::PROTOCOL_ID_TYPE::IPv4: {
                data = recvData_;
                break;
            }
            case IpHdr::PROTOCOL_ID_TYPE::ICMP: {
                data = recvData_;
                break;
            }
            case IpHdr::PROTOCOL_ID_TYPE::TCP: {
                TcpHdr* tcpHeader = reinterpret_cast<TcpHdr*>(recvData_.buf + sizeof(EthHdr) + ipHeader->len());
                if(port == tcpHeader->sPort() || port == tcpHeader->dPort())
                    data = recvData_;
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

    return data;
}

//public
vector<QString> PcapController::GetInterfaces() {
    vector<QString> ret;

    for(const auto& info : interfaceInfos_)
        ret.push_back(info.interfaceName_.c_str());

    return ret;
}

QString PcapController::GetCurrentInterface() {
    unique_lock<mutex> t(mtx_);
    return QString(cInterfaceInfo_.interfaceName_.c_str());
}

bool PcapController::SetCurrentInterface(const QString& interface) {
    unique_lock<mutex> t(mtx_);

    for(const auto& info : interfaceInfos_) {
        if(info.interfaceName_ == interface) {
            cInterfaceInfo_ = info;
            OpenPcap(interface.toStdString());
            return true;
        }
    }

    return false;
}

void PcapController::Stop() {
    pause();
}

bool PcapController::SetFilter(const QString& filter) {
    return SetPcapFilter(filter.toStdString());
}
