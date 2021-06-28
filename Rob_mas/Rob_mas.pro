DEPENDPATH += .
INCLUDEPATH += .
TARGET = Rob_mas
TEMPLATE = app
QT += network gui widgets printsupport
QT += serialport
QT += core gui
SOURCES += \
    main.cpp \
    SocketTestQ.cpp \
    tcpportlist.cpp \
    udpportlist.cpp \
    csslserver.cpp \
    ../qcustomplot/qcustomplot.cpp

HEADERS += \
    SocketTestQ.h \
    tcpportlist.h \
    udpportlist.h \
    csslserver.h \
    ../qcustomplot/qcustomplot.h

FORMS += \
    SocketTestQ.ui \
    tcpportlist.ui \
    udpportlist.ui

RESOURCES += \
    myimage.qrc

win32:RC_ICONS += icon.ico

CONFIG(release, debug|release): CONFIG += release
CONFIG(debug, debug|release): CONFIG += debug
