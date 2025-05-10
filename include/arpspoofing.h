#ifndef ARPSPOOFING_H
#define ARPSPOOFING_H

#include <list>
#include <cstdlib>
#include <chrono>

#include "pcapcontroller.h"

struct Flow {
    Ip sip_;
    Ip tip_;

    Flow();
    Flow(const QString senderIP, const QString targetIP) { sip_ = senderIP; tip_ = targetIP; }

    bool operator==(const Flow& f) { if(sip_ == f.sip_ && tip_ == f.tip_) return true; return false; }

};

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

class ArpSpoofing final : public PcapController
{
    struct JumboFramePacket {
        std::shared_ptr<uint8_t[]> buf_{};
        uint32_t size_{};
    };

    enum JumboFrameMethod{
        IpFramgent = 0,
        TCPSegment,
    };

    int MAX_MTU = 1500;
    int MAX_MSS = 1400;

    void RecvPacketThreadFunc() override;

    Mac ResolveMac(const Ip& targetIP);

    std::list<Flow> flowList_;
    std::map<Ip, Mac> arpTable_;

    void WarningMessage(const std::string& msg);
    void ErrorMessage(const std::string& msg);

    bool RegistgerArpTable(const Ip& ip);

    uint16_t MakeWord(const uint8_t& a, const uint8_t& b);

    void SetIpChecksum(PIpHdr ipHeader);
    void SetTcpChecksum(const uint16_t payloadLen, const PIpHdr ipHeader, PTcpHdr tcpHeader);
    std::vector<JumboFramePacket> JumboFrameProcessingWithIpFragment(const Packet& jPacket);
    std::vector<JumboFramePacket> JumboFrameProcessingWithTcpSegment(const Packet& jPacket);
    std::vector<JumboFramePacket> GetJumboFramePackets(const Packet& jPacket, JumboFrameMethod method = IpFramgent);

    EthArpPacket MakeEthArpPacket(const Mac& ethSmac, const Mac& ethDmac, const Mac& arpSmac, const Mac& arpTmac, const Ip& arpSip, const Ip& arpTip, const ArpHdr::OpCodeType opCode);


    bool Infect(const Mac& targetMac, const Ip& senderIP, const Ip& targetIP, const ArpHdr::OpCodeType opCode = ArpHdr::OpCodeType::Arp_Reply);
    bool Recover(const Mac& senderMac, const Mac& targetMac, const Ip& senderIP, const Ip& targetIP, const ArpHdr::OpCodeType opCode = ArpHdr::OpCodeType::Arp_Reply);
    void Relay(Packet& rPacket);


public:
    ArpSpoofing();
    ~ArpSpoofing();

    void Register(const QString senderIP, const QString targetIP);
    void Register(const Flow flow);
    void Register(const std::vector<Flow> flow);
    void Delete(const QString senderIP, const QString targetIP);
    void Delete(const Flow flow);
    void Delete(const std::vector<Flow> flow);

    std::list<Flow> GetFlows();

    void Stop() override;
    void Run();
};

#endif // ARPSPOOFING_H
