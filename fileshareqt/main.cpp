#include "mainwindow.h"
#include "services.h"
#include "logger.h"

#include <QFile>
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


    // defining our global log format -> prepends every log with [LOG]
    auto prefixFormatter = [](const QString &raw) -> QString {
        return QString("[LOG] %1").arg(raw);
    };
    Logger::registerFormatter(prefixFormatter);

    Services services;
    MainWindow w(services.auth.get(), services.file.get(), services.profile.get(), services.verify.get(), services.share.get());
    w.show();

    Logger::initialize(w.findChild<QPlainTextEdit*>("consoleTextEdit"));

    return a.exec();
}
