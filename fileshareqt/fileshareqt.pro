QT       += core gui network widgets
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets
CONFIG  += c++17

# Homebrew on macOS
macx {
    INCLUDEPATH += /opt/homebrew/include
    LIBS        += -L/opt/homebrew/lib -lsodium -lssl -lcrypto
}

# Linux / other Unix
unix:!macx {
    INCLUDEPATH += /usr/local/include
    LIBS        += -L/usr/local/lib -lsodium -lssl -lcrypto
}

# --- add our MVC include dirs so #include "Foo.h" works ---
INCLUDEPATH += \
    $$PWD/controllers \
    $$PWD/models      \
    $$PWD/utils       \
    $$PWD/views

HEADERS += \
    controllers/authcontroller.h \
    controllers/filecontroller.h \
    controllers/profilecontroller.h \
    models/crypto_utils.h \
    models/networkmanager.h \
    models/passwordstrength.h \
    utils/cryptoservice.h \
    utils/icryptoservice.h \
    utils/logger.h \
    utils/icryptoservice.h \
    utils/cryptoservice.h \
    views/mainwindow.h

SOURCES += \
    controllers/authcontroller.cpp \
    controllers/filecontroller.cpp \
    controllers/profilecontroller.cpp \
    main.cpp \
    models/crypto_utils.cpp \
    models/networkmanager.cpp \
    models/passwordstrength.cpp \
    utils/cryptoservice.cpp \
    utils/logger.cpp \
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
