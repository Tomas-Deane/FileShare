#include "logger.h"

#include <QDateTime>
#include <QFile>
#include <QTextStream>
#include <QDir>
#include <QCoreApplication>

static QFile     logFile;
static QTextStream logStream;
QPlainTextEdit*   Logger::consoleWidget = nullptr;

void Logger::initialize(QPlainTextEdit *console) {
    consoleWidget = console;
}

void Logger::ensureLogOpen() {
    if (logFile.isOpen()) return;

    QDir d(QCoreApplication::applicationDirPath());

    // cd up until fileshareqt (CWD depth might change with OS or Qt version)
    while (!d.isRoot() && d.dirName() != "fileshareqt") {
        d.cdUp();
    }

    QString targetDir = (d.dirName() == "fileshareqt")
                            ? d.absolutePath()
                            : QDir::currentPath();

    QDir().mkpath(targetDir);
    QString path = QDir(targetDir).filePath("client_debug.log");

    logFile.setFileName(path);
    logFile.open(QIODevice::Append | QIODevice::Text);
    logStream.setDevice(&logFile);
}

void Logger::log(const QString &msg) {
    ensureLogOpen();
    QString ts = QDateTime::currentDateTime().toString(Qt::ISODate);
    logStream << ts << ": " << msg << "\n";
    logStream.flush();

    if (consoleWidget) {
        consoleWidget->appendPlainText(ts + ": " + msg);
    }
}
