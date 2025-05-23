#ifndef LOGGER_H
#define LOGGER_H

#include <QPlainTextEdit>
#include <QString>

class Logger {
public:
    // call in mainwindow to set the gui log text box
    static void initialize(QPlainTextEdit *console);

    // Use everywhere to write one line.
    static void log(const QString &msg);

private:
    static QPlainTextEdit *consoleWidget;
    static void ensureLogOpen();
};

#endif // LOGGER_H
