#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QString>
#include <QByteArray>
#include <QListWidgetItem>
#include <QProgressBar>
#include <QLabel>
#include "passwordstrength.h"
#include "sharecontroller.h"
#include "sharedfilemanager.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class CryptoService;
class AuthController;
class ProfileController;
class FileController;
class VerifyController;
class NetworkManager;
class ShareController;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
// Injected dependencies:
    MainWindow(AuthController* authCtrl,
                FileController* fileCtrl,
                ProfileController* profileCtrl,
                VerifyController* verifyCtrl,
                ShareController*   shareCtrl,
                QWidget *parent = nullptr);

    ~MainWindow();

    enum TabIndex {
        Home        = 0,
        SignUp      = 1,
        Login       = 2,
        Verify      = 3,
        Upload      = 4,
        Download    = 5,
        ShareNew    = 6,
        SharesTo    = 7,
        SharesFrom  = 8,
        Profile     = 9
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

    void onListFilesResult(bool success, const QList<FileEntry> &files, const QString &message);
    void onDownloadFileResult(bool success, const QString &filename, const QByteArray &data, const QString &message);

    void on_shareFileButton_clicked();

    void on_sharesToVerifiedUsersList_itemSelectionChanged();
    // Fired when shareController returns the list of files shared TO that user
    void onSharesToFilesResult(bool success,
                               const QList<SharedFile> &shares,
                               const QString &message);

    void on_sharedFromUsersList_itemSelectionChanged();
    void onSharesFromFilesResult(bool success,
                                 const QList<SharedFile> &shares,
                                 const QString &message);

    void on_saveSharesFromFileButton_clicked();

    void on_sharesFromFilesList_itemSelectionChanged();

    /// Handler for when ShareController has finished downloading a shared file
    void on_downloadSharedFileResult(bool success,
                                     const QString &filename,
                                     const QByteArray &data,
                                     const QString &message);

    void on_tabWidget_currentChanged(int index);

    void on_signupPasswordLineEdit_textChanged(const QString &text);
    void on_changePasswordLineEdit_textChanged(const QString &text);

private:
    Ui::MainWindow        *ui;
    AuthController        *authController;
    ProfileController     *profileController;
    FileController        *fileController;
    VerifyController      *verifyController;
    ShareController       *shareController;
    SharedFileManager     *sharedFileMgr;
    PasswordStrength       pwEvaluator;

    QString                currentUploadPath;
    QByteArray             currentUploadData;

    QListWidgetItem       *pendingDeleteItem;

    QMap<QString,QByteArray> sharedDownloadCache;

    //  When the user clicks “Save” but the file isn’t yet downloaded
    bool   m_pendingSaveShare;
    QString m_pendingSaveFilename;

    void updatePasswordStrength(const QString &text,
                                QProgressBar *bar,
                                QLabel *label);

    // track the last‐active tab so we can clear it when leaving
    int m_prevTabIndex;

    // helpers for resetting UI
    void clearPage(int index);
    void refreshPage(int index);

    // helper for previewing shared files
    void previewSharedFile(const QString &filename, const QByteArray &data);

};

#endif // MAINWINDOW_H
