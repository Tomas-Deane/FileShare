#ifndef LOGGER_H
#define LOGGER_H

#include <QPlainTextEdit>
#include <QString>
#include <QByteArray>
#include <QDebug>

class Logger {
public:
    static void initialize(QPlainTextEdit *console);
    static void log(const QString &msg);

    // converts a UTF-8 encoded QByteArray to QString and logs it
    static void log(const QByteArray &msg) {
        log(QString::fromUtf8(msg));
    }

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

private:
    static QPlainTextEdit *consoleWidget;
    static void ensureLogOpen();
};

namespace Log {

// shorthand for Logger::log to log a QString message
inline void message(const QString &s) {
    Logger::log(s);
}

// shorthand for Logger::log to log a QByteArray message
inline void message(const QByteArray &b) {
    Logger::log(b);
}

// shorthand for Logger::log to log any object by converting it via QDebug
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
