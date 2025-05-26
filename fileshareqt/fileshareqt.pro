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

FORMS     += mainwindow.ui
RESOURCES += nrmc_image.png \
    resources.qrc

# Install path
qnx:    target.path = /tmp/$${TARGET}/bin
else:   unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

DISTFILES += \
    styles/style.qss
