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

// Converts a UTF-8 QByteArray to QString and logs it, but does so by walking the raw bytes with a char-pointerto illustrate basic *POINTER ARITHMETIC*
// this log function can be seen in use on line 208 in authcontroller.cpp
void Logger::log(const QByteArray &msg) {
    // Get a raw pointer to the QByteArray's data (UTF-8 bytes):
    const char *ptr    = msg.constData();
    const char *endPtr = ptr + msg.size();

    // Build a QString by reading one byte at a time:
    QString s;
    while (ptr < endPtr) {
        s.append(QChar(static_cast<unsigned char>(*ptr)));
        ptr++;
    }
    // Now delegate to the existing QString overload:
    log(s);
}

void Logger::log(const QString &msg) {
    // Simply forward to the singleton’s internal logger
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

// POINTERs and ARRAYs
// A tiny demonstration that “arrayName” is just a pointer to its first element, and that pointer arithmetic (arr + i) is identical to arr[i]
void Logger::demonstratePointers() {
    int vals[] = { 10, 20, 30, 40, 50 };
    int *ptr = vals; // exactly the same as &vals[0]

    // build a single QString showing both indexing styles
    QString s = "Pointer vs. array demo: ";

    // We know sizeof(vals)/sizeof(vals[0]) == 5
    int length = static_cast<int>(sizeof(vals) / sizeof(vals[0]));
    for (int i = 0; i < length; ++i) {
        int viaIndex    = vals[i];       // array-index style
        int viaPointer  = *(ptr + i);    // pointer arithmetic style

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
