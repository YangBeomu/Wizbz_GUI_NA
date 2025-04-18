#ifndef NETWORKCONTROLLER_H
#define NETWORKCONTROLLER_H

#include <QObject>
#include <QString>
#include <QDebug>

#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <unistd.h>

#include <vector>
#include <string>
#include <iostream>

#include <pcap.h>

#include "mac.h"
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"


class NetworkController : public QObject
{
    Q_OBJECT

    typedef struct INTERFACE_INFO{
        QString interfaceName_;
        Mac mac_;

    }InterfaceInfo;

#pragma pack(push, 1)
    struct EthArpPacket final {
        EthHdr eth_;
        ArpHdr arp_;
    };
#pragma pack(pop)


    pcap_t* pcap = nullptr;
    std::vector<InterfaceInfo> interfaceInfos_;

    void GetInterfaceInfo();
    Mac GetMac(const QString& interface,const QString targetIP);

public:
    explicit NetworkController(QObject *parent = nullptr);

    std::vector<QString> GetInterfaces();

    bool ArpSpoofing(const QString interface, const QString senderIP,const QString targetIP);
signals:
};

#endif // NETWORKCONTROLLER_H
