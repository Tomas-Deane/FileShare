QT       += core gui network widgets
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets
CONFIG  += c++17

# Homebrew on macOS
macx {
    INCLUDEPATH += /opt/homebrew/include /opt/homebrew/opt/curl/include
    LIBS        += -L/opt/homebrew/lib -lcurl -lsodium -lssl -lcrypto
}


# Linux / other Unix
unix:!macx {
    INCLUDEPATH += /usr/include
    LIBS        += -L/usr/lib -lcurl -lsodium -lssl -lcrypto
}

INCLUDEPATH += \
    $$PWD/controllers \
    $$PWD/models      \
    $$PWD/utils       \
    $$PWD/views

HEADERS += \
    controllers/authcontroller.h \
    controllers/filecontroller.h \
    controllers/profilecontroller.h \
    controllers/sharecontroller.h \
    models/crypto_utils.h \
    models/networkmanager.h \
    models/passwordstrength.h \
    utils/cache.h \
    utils/fileentry.h \
    utils/services.h \
    utils/sharedfilemanager.h \
    utils/tofumanager.h \
    utils/icryptoservice.h \
    utils/inetworkmanager.h \
    utils/logger.h \
    controllers/verifycontroller.h \
    views/mainwindow.h

SOURCES += \
    controllers/authcontroller.cpp \
    controllers/filecontroller.cpp \
    controllers/profilecontroller.cpp \
    controllers/sharecontroller.cpp \
    main.cpp \
    models/crypto_utils.cpp \
    models/networkmanager.cpp \
    models/passwordstrength.cpp \
    utils/sharedfilemanager.cpp \
    utils/tofumanager.cpp \
    utils/logger.cpp \
    controllers/verifycontroller.cpp \
    views/mainwindow.cpp

FORMS += \
    views/mainwindow.ui

RESOURCES += nrmc_image.png \
    resources.qrc

# Install path
qnx:    target.path = /tmp/$${TARGET}/bin
else:   unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

DISTFILES += \
    styles/style.qss
