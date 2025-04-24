#ifndef ARPSPOOFING_H
#define ARPSPOOFING_H

#include <list>

#include "pcapcontroller.h"

class ArpSpoofing : public PcapController
{
    void RecvPacketThreadFunc() override;

    struct FlowList {

    };

    std::list<int> flow;
    void flow();

public:
    ArpSpoofing();
};

#endif // ARPSPOOFING_H
