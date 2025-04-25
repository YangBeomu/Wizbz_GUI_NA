#ifndef ARPSPOOFING_H
#define ARPSPOOFING_H

#include <list>

#include "pcapcontroller.h"

struct Flow {
    Ip sip_;
    Ip tip_;

    Flow();
    Flow(const QString senderIP, const QString targetIP) { sip_ = senderIP; tip_ = targetIP; }

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

    Mac ResolveMac(const std::string targetIP);

    std::list<Flow> flowList_;
    bool Infect();

public:
    ArpSpoofing();

    void Register(const QString senderIP, const QString targetIP);
    void Register(const Flow flow);
    void Register(const std::vector<Flow> flow);

    std::list<Flow> GetFlows();

    void Run();
};

#endif // ARPSPOOFING_H
