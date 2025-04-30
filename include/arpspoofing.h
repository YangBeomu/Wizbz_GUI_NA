#ifndef ARPSPOOFING_H
#define ARPSPOOFING_H

#include <list>

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
    void RecvPacketThreadFunc() override;

    void ResolveMac(const std::string targetIP);

    std::list<Flow> flowList_;
    std::map<Ip, Mac> arpTable_;
    bool Infect();
    bool Recover();

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

    void Run();
};

#endif // ARPSPOOFING_H
