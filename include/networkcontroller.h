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

#include <thread>
#include <mutex>
#include <condition_variable>

#include <pcap.h>

#include "../../include/mac.h"
#include "../../include/ethhdr.h"
#include "../../include/arphdr.hpp"
#include "../../include/iphdr.hpp"
#include "../../include/tcphdr.hpp"


class NetworkController : public QObject
{
    Q_OBJECT

#pragma pack(push, 1)
    struct EthArpPacket final {
        EthHdr eth_;
        ArpHdr arp_;
    };
#pragma pack(pop)

    typedef struct INTERFACE_INFO{
        QString interfaceName_;
        Mac mac_;

    }InterfaceInfo;

    typedef struct PCAP_RECV_DATA {
        pcap_pkthdr* header{};
        u_char* buf;
    }RecvData;

    std::vector<pcap_t*> pcaps_{};
    std::vector<InterfaceInfo> interfaceInfos_{};
    InterfaceInfo cInterfaceInfo_{};
    std::vector<RecvData> recvDatas_{};

    enum {
        STATUS_ERROR,
        STATUS_INIT,
        STATUS_PAUSE,
        STATUS_PLAY,
        STATUS_END
    };

    std::thread hThread_;
    std::mutex mtx_;
    std::condition_variable cv_;
    int status_;

    void RecvPacketThreadFunc(NetworkController* nc) const;
    void OpenThread();
    //void ChangeThread();
    void play();
    void pause();
    void end();


    void GetInterfaceInfo();
    bool OpenPcap(const int timeout = 1);

    Mac GetMac(const QString& interface, const QString targetIP);
    bool ReadPacket(const QString& interface);
    std::vector<uint8_t*> GetPacket(const QString interface,const uint16_t etherType,
                                     const QString ip, const IpHdr::PROTOCOL_ID_TYPE type, const uint16_t port);

public:
    explicit NetworkController(QObject *parent = nullptr);
    ~NetworkController();

    std::vector<QString> GetInterfaces();
    bool SetCurrentInterface(const QString interface);
    QString GetCurrentInterface();

    bool ArpSpoofing(const QString interface, const QString senderIP,const QString targetIP);

signals:
};

#endif // NETWORKCONTROLLER_H
