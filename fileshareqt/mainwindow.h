// File: fileshareqt/mainwindow.h
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QString>
#include <QStringList>
#include <QByteArray>
#include <QMap>
#include <QListWidgetItem>       // <<< add this

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
    void onUploadFileResult(bool success, const QString &message);

    // Update UI when AuthController tells us user has logged in/out
    void handleLoggedIn(const QString &username);
    void handleLoggedOut();

    // New slots for change username/password results
    void onChangeUsernameResult(bool success, const QString &message);
    void onChangePasswordResult(bool success, const QString &message);

    void updateConnectionStatus(bool online);

    // Upload
    void on_selectFileButton_clicked();
    void on_uploadFileButton_clicked();

    // Download
    void on_downloadFileList_itemSelectionChanged();
    void on_downloadFileButton_clicked();

    // Delete
    void on_deleteButton_clicked();
    void onDeleteFileResult(bool success, const QString &message);

    // New slots for listing and downloading
    void onListFilesResult(bool success, const QStringList &files, const QString &message);
    void onDownloadFileResult(bool success, const QString &filename, const QByteArray &data, const QString &message);

    // Clear previews and trigger listFiles only on tab switch
    void on_tabWidget_currentChanged(int index);

private:
    Ui::MainWindow *ui;
    AuthController *authController;

    // We store the original filename here
    QString currentUploadPath;
    QByteArray currentUploadData;

    // filenames → decrypted data
    QMap<QString, QByteArray> downloadCache;

    // **NEW** pointer to the item we're about to delete
    QListWidgetItem *pendingDeleteItem;
};

#endif // MAINWINDOW_H
