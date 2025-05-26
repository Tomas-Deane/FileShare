#include "mainwindow.h"
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

    MainWindow w;
    w.show();
    return a.exec();
}
