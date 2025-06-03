#ifndef LOGGER_H
#define LOGGER_H

#include <QPlainTextEdit>
#include <QString>
#include <QByteArray>
#include <QDebug>

class Logger {
public:
    // still keep these two static for everyone else to call
    static void initialize(QPlainTextEdit *console);
    static void log(const QString &msg);

    // converts a UTF-8 QByteArray to QString and logs it
    static void log(const QByteArray &msg);

    // uses QDebug to stream any type T into a QString and logs it
    template<typename T>
    static void log(const T &obj) {
        QString s;
        {
            QDebug dbg(&s);
            dbg << obj;
        }
        log(s);
    }

    static void demonstratePointers();

private:
    // private constructor enforces singleton
    Logger() : consoleWidget(nullptr) {}

    // singleton accessor
    static Logger &instance() {
        static Logger inst;
        return inst;
    }

    QPlainTextEdit *consoleWidget;

    static QFile     logFile;
    static QTextStream logStream;

    static void ensureLogOpen();

    void logInternal(const QString &msg);
};

// same “Log::message” shorthands as before:
namespace Log {
inline void message(const QString &s) {
    Logger::log(s);
}
inline void message(const QByteArray &b) {
    Logger::log(b);
}
template<typename T>
inline void message(const T &obj) {
    QString s;
    {
        QDebug dbg(&s);
        dbg << obj;
    }
    Logger::log(s);
    }
}

#endif // LOGGER_H
