#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QString>
#include <QStringList>
#include <QByteArray>
#include <QMap>
#include <QListWidgetItem>
#include <QProgressBar>
#include <QLabel>
#include "passwordstrength.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class CryptoService;
class AuthController;
class ProfileController;
class FileController;
class NetworkManager;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
// Injected dependencies:
    MainWindow(AuthController* authCtrl,
                FileController* fileCtrl,
                ProfileController* profileCtrl,
                QWidget *parent = nullptr);

    ~MainWindow();

    enum TabIndex {
        Home     = 0,
        Signup   = 1,
        Login    = 2,
        Upload   = 3,
        Download = 4,
        Share    = 5,
        Profile  = 6
    };

private slots:
    void on_signupButton_clicked();
    void on_loginButton_clicked();
    void on_logOutButton_clicked();
    void on_changeUsernameButton_clicked();
    void on_changePasswordButton_clicked();
    void onUploadFileResult(bool success, const QString &message);

    void handleLoggedIn(const QString &username);
    void handleLoggedOut();

    void onChangeUsernameResult(bool success, const QString &message);
    void onChangePasswordResult(bool success, const QString &message);

    void updateConnectionStatus(bool online);

    void on_selectFileButton_clicked();
    void on_uploadFileButton_clicked();

    void on_downloadFileList_itemSelectionChanged();
    void on_downloadFileButton_clicked();

    void on_deleteButton_clicked();
    void onDeleteFileResult(bool success, const QString &message);

    void onListFilesResult(bool success, const QStringList &files, const QString &message);
    void onDownloadFileResult(bool success, const QString &filename, const QByteArray &data, const QString &message);

    void on_tabWidget_currentChanged(int index);

    void on_signupPasswordLineEdit_textChanged(const QString &text);
    void on_changePasswordLineEdit_textChanged(const QString &text);

private:
    Ui::MainWindow        *ui;
    AuthController        *authController;
    ProfileController     *profileController;
    FileController        *fileController;
    PasswordStrength       pwEvaluator;

    QString                currentUploadPath;
    QByteArray             currentUploadData;

    QListWidgetItem       *pendingDeleteItem;

    void updatePasswordStrength(const QString &text,
                                QProgressBar *bar,
                                QLabel *label);
};

#endif // MAINWINDOW_H
