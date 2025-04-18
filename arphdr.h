#pragma once

#include <uchar.h>

#include "mac.h"
#include "ip.h"

#pragma pack(push, 1)
typedef struct ARP_HEDAER final {
    static constexpr u_char ETHERNET = 1;
    static constexpr u_char ETHERNET_LEN = 6;
    static constexpr u_char PROTOCOL_LEN = 4;


    u_int16_t harwareType_;
    u_int16_t protocolType_;
    u_char hardwareSize_;
    u_char protocolSize_;
    u_int16_t opCode_;
    Mac smac_;
    Ip sip_;
    Mac dmac_;
    Ip dip_;



    Mac dmac() { return dmac_; }
    Mac smac() { return smac_; }
    u_char hardwareSize() { return hardwareSize_; }
    u_char protocolSize() { return protocolSize_; }
    u_int16_t opCode() {return opCode_; }

    //opcode types
    typedef enum OPCODE_TYPE{
        Arp_Request = 1,
        Arp_Reply,
        RArp_Request,
        Rarp_Reply,
        DRarp_Request,
        DRarp_Reply,
        Drarp_Error,
        InArp_Request,
        InArp_Reply
    }OpCodeType;

}ArpHdr;

typedef ArpHdr *PArpHdr;
#pragma pack(pop)
