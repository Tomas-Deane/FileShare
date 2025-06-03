#include "mainwindow.h"
#include "services.h"

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

    Services services;
    MainWindow w(services.auth.get(), services.file.get(), services.profile.get(), services.verify.get(), services.share.get());
    w.show();

    return a.exec();
}
