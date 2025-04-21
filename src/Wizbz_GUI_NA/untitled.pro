QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

LIBS += -lpcap


# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    ../../include/ethhdr.cpp \
    ../../include/ip.cpp \
    ../../include/mac.cpp \
    ../../include/networkcontroller.cpp \
    main.cpp \
    widget.cpp

HEADERS += \
    ../../include/arphdr.hpp \
    ../../include/ethhdr.h \
    ../../include/ip.h \
    ../../include/iphdr.hpp \
    ../../include/mac.h \
    ../../include/networkcontroller.h \
    ../../include/tcphdr.hpp \
    widget.h

FORMS += \
    widget.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
