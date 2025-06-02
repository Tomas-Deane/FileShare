#include "mainwindow.h"
#include "networkmanager.h"
#include "cryptoservice.h"
#include "authcontroller.h"
#include "profilecontroller.h"
#include "filecontroller.h"
#include "verifycontroller.h"

#include <QFile>
#include <QDebug>
#include <QApplication>
#include <memory>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);


        QFile styleFile(":/styles/style.qss");
    if (styleFile.open(QFile::ReadOnly | QFile::Text)) {
        QString style = styleFile.readAll();
        a.setStyleSheet(style);
    } else {
        qWarning() << "Could not load style sheet!";
    }

    // ——— DI with unique_ptr ———
    auto net = std::make_unique<NetworkManager>();
    auto cs  = std::make_unique<CryptoService>();

    auto ac = std::make_unique<AuthController>(net.get(), cs.get());
    auto pc = std::make_unique<ProfileController>(net.get(), ac.get(), cs.get());
    auto fc = std::make_unique<FileController>(net.get(), ac.get(), cs.get());
    auto vc = std::make_unique<VerifyController>(net.get(), ac.get(), cs.get());

    MainWindow w(ac.get(), fc.get(), pc.get(), vc.get());
    w.show();

    return a.exec();
}
