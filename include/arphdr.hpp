#pragma once

#include <arpa/inet.h>

#include "mac.h"
#include "ip.h"

#pragma pack(push, 1)
typedef struct ARP_HEDAER final {
    static constexpr uint8_t ETHERNET = 1;
    static constexpr uint8_t ETHERNET_LEN = 6;
    static constexpr uint8_t PROTOCOL_LEN = 4;

    uint16_t harwareType_;
    uint16_t protocolType_;
    uint8_t hardwareSize_;
    uint8_t protocolSize_;
    uint16_t opCode_;
    Mac smac_;
    Ip sip_;
    Mac tmac_;
    Ip tip_;

    Mac tmac() { return tmac_; }
    Mac smac() { return smac_; }
    uint8_t hardwareSize() { return hardwareSize_; }
    uint8_t protocolSize() { return protocolSize_; }
    uint16_t opCode() {return ntohs(opCode_); }

    // std::string sip() {
    //     char buf[INET_ADDRSTRLEN]{};

    //     inet_ntop(AF_INET, &sip_, buf, sizeof(buf));
    //     return std::string(buf);
    // }

    // std::string tip() {
    //     char buf[INET_ADDRSTRLEN]{};

    //     inet_ntop(AF_INET, &tip_, buf, sizeof(buf));
    //     return std::string(buf);
    // }

    std::string sip() { return std::string(sip_); }
    std::string tip() { return std::string(tip_); }

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
