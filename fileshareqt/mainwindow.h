// File: fileshareqt/mainwindow.h
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QString>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class AuthController;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_signupButton_clicked();
    void on_loginButton_clicked();
    void on_logOutButton_clicked();
    void on_changeUsernameButton_clicked();
    void on_changePasswordButton_clicked();
    void on_pushButton_2_clicked();            // Upload File button
    void onUploadFileResult(bool success, const QString &message);

    // Update UI when AuthController tells us user has logged in/out
    void handleLoggedIn(const QString &username);
    void handleLoggedOut();

    // New slots for change username/password results
    void onChangeUsernameResult(bool success, const QString &message);
    void onChangePasswordResult(bool success, const QString &message);

    void updateConnectionStatus(bool online);

private:
    Ui::MainWindow *ui;
    AuthController *authController;
};

#endif // MAINWINDOW_H
