#pragma once

#include <uchar.h>

#include "ip.h"

typedef struct IP_HEADER final {
    union {
        struct {
            u_int16_t version_ : 4;
            u_int16_t headerLen_ : 4;
            u_int16_t TOS_ : 8;
        };
    };

    u_int16_t totalPacketLen_;
    u_int16_t id;

    union {
        struct {
            u_int16_t flags : 3;
            u_int16_t fragOffset_ : 13;
        };
    };

    Ip sIp_;
    Ip dIp_;
}IpHdr;

typedef IpHdr* PIpHdr;
