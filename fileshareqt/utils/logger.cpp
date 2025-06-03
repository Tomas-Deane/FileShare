#include "logger.h"

#include <QDateTime>
#include <QFile>
#include <QTextStream>
#include <QDir>
#include <QCoreApplication>

// static data for the log file on disk:
QFile     Logger::logFile;
QTextStream Logger::logStream;

void Logger::initialize(QPlainTextEdit *console)
{
    Logger::instance().consoleWidget = console;
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

void Logger::log(const QString &msg)
{
    Logger::instance().logInternal(msg);
}

void Logger::logInternal(const QString &msg)
{
    Logger::ensureLogOpen();

    QString ts = QDateTime::currentDateTime().toString(Qt::ISODate);

    logStream << ts << ": " << msg << "\n";
    logStream.flush();

// explicit use of this pointer
    if (this->consoleWidget) {
        this->consoleWidget->appendPlainText(ts + ": " + msg);
    }
}
