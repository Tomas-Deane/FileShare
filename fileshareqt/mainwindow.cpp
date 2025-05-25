#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "authcontroller.h"
#include "logger.h"

#include <sodium.h>
#include <QPixmap>
#include <QTimer>
#include <QFileDialog>
#include <QFileInfo>
#include <QMimeDatabase>
#include <QFile>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , authController(new AuthController(this))
    , pendingDeleteItem(nullptr)           // <<< initialize here
{
    ui->setupUi(this);

    // Only refresh list when entering the Download tab, clear previews on leave
    connect(ui->tabWidget, &QTabWidget::currentChanged,
            this, &MainWindow::on_tabWidget_currentChanged);

    // Delete button
    connect(ui->deleteButton, &QPushButton::clicked,
            this, &MainWindow::on_deleteButton_clicked);

    // Handle delete results
    connect(authController, &AuthController::deleteFileResult,
            this, &MainWindow::onDeleteFileResult);

    // Console logger
    Logger::initialize(ui->consoleTextEdit);
    if (sodium_init() < 0) {
        Logger::log("sodium_init() failed");
    } else {
        Logger::log("sodium initialized");
    }

    // Core connections
    connect(authController, &AuthController::loggedIn,
            this, &MainWindow::handleLoggedIn);
    connect(authController, &AuthController::loggedOut,
            this, &MainWindow::handleLoggedOut);
    connect(authController, &AuthController::changeUsernameResult,
            this, &MainWindow::onChangeUsernameResult);
    connect(authController, &AuthController::changePasswordResult,
            this, &MainWindow::onChangePasswordResult);
    connect(authController, &AuthController::uploadFileResult,
            this, &MainWindow::onUploadFileResult);
    connect(authController, &AuthController::listFilesResult,
            this, &MainWindow::onListFilesResult);
    connect(authController, &AuthController::downloadFileResult,
            this, &MainWindow::onDownloadFileResult);
    connect(authController, &AuthController::connectionStatusChanged,
            this, &MainWindow::updateConnectionStatus);

    Logger::log("UI setup complete");
    QTimer::singleShot(0, this, [this]{
        authController->checkConnection();
    });
}

MainWindow::~MainWindow()
{
    Logger::log("Application exiting");
    delete ui;
}

void MainWindow::on_signupButton_clicked()
{
    authController->signup(ui->usernameLineEdit->text(),
                           ui->passwordLineEdit->text());
}

void MainWindow::on_loginButton_clicked()
{
    authController->login(ui->usernameLineEdit->text(),
                          ui->passwordLineEdit->text());
}

void MainWindow::on_logOutButton_clicked()
{
    authController->logout();
}

void MainWindow::handleLoggedIn(const QString &username)
{
    ui->loggedInLabel->setText("Logged in as " + username);
    ui->usernameLabel->setText("Username: " + username);
    // don't auto-refresh here anymore
}

void MainWindow::handleLoggedOut()
{
    ui->loggedInLabel->setText("Not logged in");
    ui->usernameLabel->setText("Username: ");
    ui->downloadFileList->clear();
    ui->downloadFileNameLabel->setText("No file selected");
    ui->downloadFileTypeLabel->setText("-");
    downloadCache.clear();
}

void MainWindow::on_changeUsernameButton_clicked()
{
    authController->changeUsername(ui->changeUsernameLineEdit->text());
}

void MainWindow::on_changePasswordButton_clicked()
{
    authController->changePassword(ui->changePasswordLineEdit->text());
}

void MainWindow::onChangeUsernameResult(bool success, const QString &message)
{
    Logger::log(success
                    ? "Username changed successfully"
                    : "Failed to change username: " + message);
}

void MainWindow::onChangePasswordResult(bool success, const QString &message)
{
    Logger::log(success
                    ? "Password changed successfully"
                    : "Failed to change password: " + message);
}

void MainWindow::onUploadFileResult(bool success, const QString &message)
{
    if (success) {
        Logger::log("File uploaded successfully");
        // don't auto-refresh list here anymore
    } else {
        Logger::log("File upload failed: " + message);
    }
}

void MainWindow::updateConnectionStatus(bool online)
{
    ui->serverConnectionLabel->setText(
        online ? "Server Connection: Online"
               : "Server Connection: Offline"
        );
}

void MainWindow::on_selectFileButton_clicked()
{
    QString fullPath = QFileDialog::getOpenFileName(
        this, tr("Select a file to upload")
        );
    if (fullPath.isEmpty()) return;

    QFileInfo fi(fullPath);
    currentUploadPath = fi.fileName();
    ui->fileNameLabel->setText(currentUploadPath);
    ui->fileTypeLabel->setText(fi.suffix());

    QFile f(fullPath);
    if (!f.open(QIODevice::ReadOnly)) {
        Logger::log("Cannot open file for preview");
        return;
    }
    currentUploadData = f.readAll();
    f.close();

    QMimeDatabase db;
    auto mime = db.mimeTypeForFile(fi);
    if (mime.name().startsWith("text/")) {
        ui->uploadTextPreview->setPlainText(QString::fromUtf8(currentUploadData));
        ui->uploadPreviewStack->setCurrentIndex(0);
    }
    else if (mime.name().startsWith("image/")) {
        QPixmap pix;
        pix.loadFromData(currentUploadData);
        ui->uploadImagePreview->setPixmap(
            pix.scaled(ui->uploadImagePreview->size(),
                       Qt::KeepAspectRatio,
                       Qt::SmoothTransformation)
            );
        ui->uploadPreviewStack->setCurrentIndex(1);
    }
    else {
        ui->uploadTextPreview->setPlainText(tr("No preview available"));
        ui->uploadPreviewStack->setCurrentIndex(0);
    }
}

void MainWindow::on_uploadFileButton_clicked()
{
    if (currentUploadData.isEmpty() || currentUploadPath.isEmpty()) {
        Logger::log("No file selected");
        return;
    }
    QString b64 = QString::fromUtf8(currentUploadData.toBase64());
    authController->uploadFile(currentUploadPath, b64);
}

void MainWindow::onListFilesResult(bool success,
                                   const QStringList &files,
                                   const QString &message)
{
    if (!success) {
        Logger::log("Failed to list files: " + message);
        return;
    }
    ui->downloadFileList->clear();
    ui->downloadFileList->addItems(files);
    downloadCache.clear();
    ui->downloadFileNameLabel->setText("No file selected");
    ui->downloadFileTypeLabel->setText("-");
    ui->downloadPreviewStack->setCurrentIndex(0);
}

void MainWindow::on_downloadFileList_itemSelectionChanged()
{
    // Figure out if there's a current selection
    auto item = ui->downloadFileList->currentItem();
    bool hasOne = (item != nullptr);

    // Enable Delete only if a file is selected
    ui->deleteButton->setEnabled(hasOne);

    // If nothing’s selected, clear all the labels/previews and bail
    if (!item) {
        ui->downloadFileNameLabel->setText("No file selected");
        ui->downloadFileTypeLabel->setText("-");
        ui->downloadTextPreview->clear();
        ui->downloadImagePreview->clear();
        ui->downloadImagePreview->setText(tr("No Image File Selected"));
        ui->downloadPreviewStack->setCurrentIndex(0);
        return;
    }

    // There is a selection — update filename/type immediately
    const QString name = item->text();
    ui->downloadFileNameLabel->setText(name);
    ui->downloadFileTypeLabel->setText(QFileInfo(name).suffix());

    // See if we've already cached the data
    const QByteArray data = downloadCache.value(name);
    if (data.isEmpty()) {
        authController->downloadFile(name);
        return;
    }

    // We have the data — show it
    QMimeDatabase db;
    auto mime = db.mimeTypeForFile(name);
    if (mime.name().startsWith("text/")) {
        ui->downloadTextPreview->setPlainText(QString::fromUtf8(data));
        ui->downloadPreviewStack->setCurrentIndex(0);
    }
    else if (mime.name().startsWith("image/")) {
        QPixmap pix;
        pix.loadFromData(data);
        ui->downloadImagePreview->setPixmap(
            pix.scaled(ui->downloadImagePreview->size(),
                       Qt::KeepAspectRatio,
                       Qt::SmoothTransformation)
            );
        ui->downloadPreviewStack->setCurrentIndex(1);
    }
    else {
        ui->downloadTextPreview->setPlainText(tr("No preview"));
        ui->downloadPreviewStack->setCurrentIndex(0);
    }
}


void MainWindow::onDownloadFileResult(bool success,
                                      const QString &filename,
                                      const QByteArray &data,
                                      const QString &message)
{
    if (!success) {
        Logger::log("Failed to download '" + filename + "': " + message);
        return;
    }

    downloadCache.insert(filename, data);

    auto item = ui->downloadFileList->currentItem();
    if (item && item->text() == filename) {
        on_downloadFileList_itemSelectionChanged();
    }
}

void MainWindow::on_downloadFileButton_clicked()
{
    auto item = ui->downloadFileList->currentItem();
    if (!item) {
        Logger::log("No file selected to download");
        return;
    }
    const QString filename = item->text();
    const QByteArray data = downloadCache.value(filename);
    if (data.isEmpty()) {
        Logger::log("No data available for '" + filename + "'");
        return;
    }

    // Ask the user where to save
    QString path = QFileDialog::getSaveFileName(this,
                                                tr("Save File As"), filename);
    if (path.isEmpty()) return;

    QFile f(path);
    if (!f.open(QIODevice::WriteOnly)) {
        Logger::log("Failed to open file for writing: " + path);
        return;
    }
    f.write(data);
    f.close();
    Logger::log("File saved to " + path);
}

void MainWindow::on_deleteButton_clicked()
{
    // capture the exact item the user clicked on
    QListWidgetItem *item = ui->downloadFileList->currentItem();
    if (!item) return;
    pendingDeleteItem = item;
    authController->deleteFile(item->text());
}

void MainWindow::onDeleteFileResult(bool success, const QString &message)
{
    if (!success) {
        Logger::log("Failed to delete file: " + message);
        return;
    }

    if (pendingDeleteItem) {
        int row = ui->downloadFileList->row(pendingDeleteItem);

        ui->downloadFileList->blockSignals(true);
        delete ui->downloadFileList->takeItem(row);
        ui->downloadFileList->blockSignals(false);

        pendingDeleteItem = nullptr;
    }

    ui->downloadFileList->setCurrentItem(nullptr);
    ui->deleteButton->setEnabled(false);

    ui->downloadFileNameLabel->setText("No file selected");
    ui->downloadFileTypeLabel->setText("-");
    ui->downloadPreviewStack->setCurrentIndex(0);

    Logger::log("File deleted successfully");
}

void MainWindow::on_tabWidget_currentChanged(int index)
{
    constexpr int uploadIndex = 2;
    constexpr int downloadIndex = 3;

    if (index != uploadIndex) {
        // Clear upload preview + reset labels and state
        ui->fileNameLabel->setText(tr("No file selected"));
        ui->fileTypeLabel->setText(tr("-"));
        ui->uploadTextPreview->clear();
        ui->uploadImagePreview->clear();
        ui->uploadImagePreview->setText(tr("No Image File Selected"));
        ui->uploadPreviewStack->setCurrentIndex(1);
        currentUploadData.clear();
        currentUploadPath.clear();
    }

    if (index == downloadIndex) {
           // Clear all of the old preview before refreshing the list:
         ui->downloadTextPreview->clear();
         ui->downloadImagePreview->clear();
         ui->downloadImagePreview->setText(tr("No Image File Selected"));
         ui->downloadPreviewStack->setCurrentIndex(0);

        // Now fetch the up-to-date file list
        authController->listFiles();
       }

    //     // (Optional) if you want to make sure it's also wiped when leaving Download:
    // else {
    //     ui->downloadTextPreview->clear();
    //     ui->downloadImagePreview->clear();
    //     ui->downloadImagePreview->setText(tr("No Image File Selected"));
    //     ui->downloadPreviewStack->setCurrentIndex(0);
    // }
}
