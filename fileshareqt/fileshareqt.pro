QT       += core gui network widgets

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

# Fallback include/lib paths if pkg-config isn't found:
macx {
    INCLUDEPATH += /opt/homebrew/include
    LIBS        += -L/opt/homebrew/lib -lsodium
} else {
    INCLUDEPATH += /usr/local/include
    LIBS        += -L/usr/local/lib -lsodium
}

win32 {
    INCLUDEPATH += "C:/Users/darah/MyRepos/vcpkg/installed/x64-windows/include"
    LIBS        += "C:/Users/darah/MyRepos/vcpkg/installed/x64-windows/lib/libsodium.lib"
}

# Link OpenSSL and libsodium
LIBS += -lssl -lcrypto

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

qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
    nrmc_image.png
