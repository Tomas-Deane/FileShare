#ifndef LOGGER_H
#define LOGGER_H

#include <QPlainTextEdit>
#include <QString>
#include <QByteArray>
#include <QDebug>
#include <memory>
#include <vector>

// class template
// a small, reusable history buffer
template<typename T, size_t Capacity>
class HistoryBuffer {
public:
    // Push a new element onto the buffer. if we exceed Capacity, discard oldest
    void push(const T &item) {
        if (data.size() < Capacity) {
            data.push_back(item);
        } else {
            // shift left by one
            for (size_t i = 1; i < Capacity; ++i) {
                data[i - 1] = std::move(data[i]);
            }
            data[Capacity - 1] = item;
        }
    }

    // Return all stored elements, in insertion order (oldest first)
    const std::vector<T>& all() const {
        return data;
    }

    // Clear out everything
    void clear() {
        data.clear();
    }

private:
    std::vector<T> data;
};

class Logger {
public:
    // still keep these two static for everyone else to call
    static void initialize(QPlainTextEdit *console);
    static void log(const QString &msg);
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

    // function pointer that takes a raw QString and returns a formatted QString
    using LogFormatter = QString (*)(const QString &raw);

    // log with an explicit formatter (passed as a function pointer)
    static void logWithFormatter(const QString &msg, LogFormatter fmt);

    // register a global formatter (called inside every log call)
    static void registerFormatter(LogFormatter fmt);

    // choose a formatter at runtime (returns a function pointer)
    static LogFormatter chooseFormatter(bool uppercase);

    static void demonstratePointers();

    // a buffer that keeps the last 1000 messages by default
    static std::shared_ptr<HistoryBuffer<QString, 1000>> getHistory();

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

    // replaced vector<QString> with HistoryBuffer<QString,1000>
    static std::shared_ptr<HistoryBuffer<QString, 1000>> s_history;

    void logInternal(const QString &msg);

    // hold the currently‐registered formatter (default = identity)
    static LogFormatter s_formatter;
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
