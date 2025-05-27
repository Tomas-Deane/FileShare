#include "mainwindow.h"
#include "networkmanager.h"
#include "cryptoservice.h"
#include "authcontroller.h"
#include "profilecontroller.h"
#include "filecontroller.h"

#include <QFile>
#include <QDebug>
#include <QApplication>

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

    // ——— manual DI ———
    // note: parent ownership set to 'w' so Qt will delete them
    INetworkManager  *net = new NetworkManager(nullptr);
    ICryptoService   *cs  = new CryptoService();

    AuthController    *ac = new AuthController(net, cs, nullptr);
    ProfileController *pc = new ProfileController(net, ac, cs, nullptr);
    FileController    *fc = new FileController(net, ac, cs, nullptr);

    MainWindow w(ac, fc, pc);
    w.show();
    return a.exec();
}
