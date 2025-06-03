#include "logger.h"

#include <QDateTime>
#include <QFile>
#include <QTextStream>
#include <QDir>
#include <QCoreApplication>

// static data for the log file on disk:
QFile     Logger::logFile;
QTextStream Logger::logStream;

// initialize the global formatter to “identity” (no changes)
Logger::LogFormatter Logger::s_formatter = nullptr;

void Logger::initialize(QPlainTextEdit *console)
{
    Logger::instance().consoleWidget = console;
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

// Convert QByteArray→QString by pointer arithmetic (unchanged)
void Logger::log(const QByteArray &msg) {
    const char *ptr    = msg.constData();
    const char *endPtr = ptr + msg.size();

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
    Logger::instance().logInternal(toWrite);
}

// Log with a one-off formatter (demonstrates passing a function pointer as an argument)
void Logger::logWithFormatter(const QString &msg, LogFormatter fmt)
{
    if (fmt) {
        QString transformed = fmt(msg);
        Logger::instance().logInternal(transformed);
    } else {
        // If fmt == nullptr, behave like regular log:
        Logger::instance().logInternal(msg);
    }
}

// Register (or replace) a global formatter
void Logger::registerFormatter(LogFormatter fmt)
{
    s_formatter = fmt;
}

// return one of two built-in formatters based on a flag
Logger::LogFormatter Logger::chooseFormatter(bool uppercase)
{
    // Forward‐declare the two static “formatter” helpers below:
    static auto identityFormatter = [](const QString &in) -> QString {
        return in;
    };

    static auto uppercaseFormatter = [](const QString &in) -> QString {
        return in.toUpper();
    };

    return uppercase ? uppercaseFormatter : identityFormatter;
}

// internal implementation that actually writes to file + console
void Logger::logInternal(const QString &msg)
{
    ensureLogOpen();

    QString ts = QDateTime::currentDateTime().toString(Qt::ISODate);

    logStream << ts << ": " << msg << "\n";
    logStream.flush();

    if (this->consoleWidget) {
        this->consoleWidget->appendPlainText(ts + ": " + msg);
    }
}

// demonstartion function for pointers and/vs arrays
void Logger::demonstratePointers() {
    int vals[] = { 10, 20, 30, 40, 50 };
    int *ptr = vals;

    QString s = "Pointer vs. array demo: ";
    int length = static_cast<int>(sizeof(vals) / sizeof(vals[0]));
    for (int i = 0; i < length; ++i) {
        int viaIndex    = vals[i];
        int viaPointer  = *(ptr + i);

        s += QString("arr[%1]=%2, *(arr+%1)=%3")
                 .arg(i)
                 .arg(viaIndex)
                 .arg(viaPointer);

        if (i < length - 1) {
            s += "; ";
        }
    }
    Logger::log(s);
}
