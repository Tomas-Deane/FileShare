#include "logger.h"

#include <QDateTime>
#include <QFile>
#include <QTextStream>
#include <QDir>
#include <QCoreApplication>
#include <memory>
#include <vector>

// static data for the log file on disk:
QFile     Logger::logFile;
QTextStream Logger::logStream;

std::shared_ptr<std::vector<QString>> Logger::s_history = nullptr;

// initialise the global formatter to “identity” (no changes)
Logger::LogFormatter Logger::s_formatter = nullptr;

void Logger::initialise(QPlainTextEdit *console)
{
    Logger::instance().consoleWidget = console;
    // if history isn’t already allocated, give it one
    if (!s_history) {
        s_history = std::make_shared<std::vector<QString>>();
    }
}

void Logger::ensureLogOpen() {
    if (logFile.isOpen()) return;

    QDir d(QCoreApplication::applicationDirPath());
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

// Convert QByteArray QString by pointer arithmetic
void Logger::log( QByteArray &msg) {
    char *ptr    = msg.data();
    char *endPtr = ptr + msg.size();

    QString s;
    while (ptr < endPtr) {
        s.append(QChar(static_cast<unsigned char>(*ptr)));
        ptr++;
    }
    log(s);
}

// apply global formatter (if any) then delegate
void Logger::log(const QString &msg) {
    QString toWrite = msg;
    if (s_formatter) {
        // apply the registered formatter first
        toWrite = s_formatter(msg);
    }
    // append to the in‐memory history first
    if (s_history) {
        s_history->push_back(toWrite);
    }
    Logger::instance().logInternal(toWrite);
}

// Register (or replace) a global formatter
void Logger::registerFormatter(LogFormatter fmt)
{
    // setting the registered formatter (prefixFormatter)
    s_formatter = fmt;
}

// internal implementation that actually writes to file + console
void Logger::logInternal(const QString &msg)
{
    ensureLogOpen();

    QString ts = QDateTime::currentDateTime().toString(Qt::ISODate);

    logStream << ts << ": " << msg << "\n";
    logStream.flush();

// this pointer
    if (this->consoleWidget) {
        this->consoleWidget->appendPlainText(ts + ": " + msg);
    }
}

std::shared_ptr<std::vector<QString>> Logger::getHistory()
{
    // If initialise hasn’t run yet, create it on‐demand
    if (!s_history) {
        s_history = std::make_shared<std::vector<QString>>();
    }
    return s_history;
}

// demonstration function for pointers and/vs arrays
void Logger::demonstratePointers()
{
    int vals[] = { 10, 20, 30, 40, 50 };
    int *ptr = vals;

    // access element 0 in two ways
    int viaIndex   = vals[0];
    int viaPointer = *(ptr);

    qDebug() << "vals[0] =" << viaIndex << ", *(ptr+0) =" << viaPointer;
}
