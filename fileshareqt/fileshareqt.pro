
QT       += core gui network widgets

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

# Suppress deprecated socket API warnings on Windows
win32 {
    DEFINES += _WINSOCK_DEPRECATED_NO_WARNINGS

    # Link against WinSock2, libsodium and OpenSSL
    LIBS += -lWs2_32 \
            -lsodium \
            -lssl \
            -lcrypto
}

# macOS (Homebrew)
macx {
    INCLUDEPATH += /opt/homebrew/include
    LIBS        += -L/opt/homebrew/lib -lsodium -lssl -lcrypto
}

# Linux fallback
unix:!macx:!win32 {
    INCLUDEPATH += /usr/local/include
    LIBS        += -L/usr/local/lib -lsodium -lssl -lcrypto
}

# Project sources and headers
SOURCES += \
    authcontroller.cpp \
    crypto_utils.cpp \
    logger.cpp \
    main.cpp \
    mainwindow.cpp \
    networkmanager.cpp

HEADERS += \
    authcontroller.h \
    crypto_utils.h \
    logger.h \
    mainwindow.h \
    networkmanager.h

FORMS += \
    mainwindow.ui

RESOURCES += \
    nrmc_image.png

# Installation paths
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
