#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QString>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class NetworkManager;
class AuthController;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onServerConnected();
    void onServerDisconnected();
    //  slots for button clicks
    void on_signupButton_clicked();
    void on_loginButton_clicked();

private:
    Ui::MainWindow      *ui;
    NetworkManager      *networkManager;
    AuthController      *authController;
};

#endif // MAINWINDOW_H
