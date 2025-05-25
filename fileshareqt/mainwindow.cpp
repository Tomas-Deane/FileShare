// File: fileshareqt/mainwindow.cpp
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "authcontroller.h"
#include "logger.h"
#include <sodium.h>
#include <QPixmap>
#include <QSizePolicy>
#include <QTimer>
#include <QFileDialog>
#include <QFile>
#include <QImageReader>
#include <QMimeDatabase>


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , authController(new AuthController(this))
{
    ui->setupUi(this);

    // Enable buttons
    ui->signupButton->setEnabled(true);
    ui->loginButton->setEnabled(true);

    // Logo setup
    ui->label->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
    ui->label->setMinimumSize(0, 0);
    ui->label->setScaledContents(true);
    QPixmap pix(":/nrmc_image.png");
    ui->label->setPixmap(pix);

    // Console logger
    Logger::initialize(ui->consoleTextEdit);

    if (sodium_init() < 0) {
        Logger::log("sodium_init() failed");
    } else {
        Logger::log("sodium initialized");
    }

    // Connect UI to AuthController state signals
    connect(authController, &AuthController::loggedIn,
            this, &MainWindow::handleLoggedIn);
    connect(authController, &AuthController::loggedOut,
            this, &MainWindow::handleLoggedOut);

    // Connect change‐username/password result signals
    connect(authController, &AuthController::changeUsernameResult,
            this, &MainWindow::onChangeUsernameResult);
    connect(authController, &AuthController::changePasswordResult,
            this, &MainWindow::onChangePasswordResult);

    // Connect upload file result
    connect(authController, &AuthController::uploadFileResult,
            this, &MainWindow::onUploadFileResult);

    // Update connection status label whenever it changes
    connect(authController, &AuthController::connectionStatusChanged,
            this, &MainWindow::updateConnectionStatus);

    Logger::log("UI setup complete");

    // Immediately check server connection on launch
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
    const QString username = ui->usernameLineEdit->text();
    const QString password = ui->passwordLineEdit->text();
    authController->signup(username, password);
}

void MainWindow::on_loginButton_clicked()
{
    const QString username = ui->usernameLineEdit->text();
    const QString password = ui->passwordLineEdit->text();
    authController->login(username, password);
}

void MainWindow::on_logOutButton_clicked()
{
    authController->logout();
}

void MainWindow::handleLoggedIn(const QString &username)
{
    ui->loggedInLabel->setText("Logged in as " + username);
    ui->usernameLabel->setText("Username: " + username);
}

void MainWindow::handleLoggedOut()
{
    ui->loggedInLabel->setText("Not logged in");
    ui->usernameLabel->setText("Username: ");
}

void MainWindow::on_changeUsernameButton_clicked()
{
    const QString newUsername = ui->changeUsernameLineEdit->text();
    authController->changeUsername(newUsername);
}

void MainWindow::on_changePasswordButton_clicked()
{
    const QString newPassword = ui->changePasswordLineEdit->text();
    authController->changePassword(newPassword);
}

void MainWindow::onChangeUsernameResult(bool success, const QString &message)
{
    if (success) {
        Logger::log("Username changed successfully");
    } else {
        Logger::log("Failed to change username: " + message);
    }
}

void MainWindow::onChangePasswordResult(bool success, const QString &message)
{
    if (success) {
        Logger::log("Password changed successfully");
    } else {
        Logger::log("Failed to change password: " + message);
    }
}

// void MainWindow::on_pushButton_2_clicked()
// {
//     const QString contents = ui->fileContentsLineEdit->text();
//     authController->uploadFile(contents);
// }

void MainWindow::onUploadFileResult(bool success, const QString &message)
{
    if (success) {
        Logger::log("File uploaded successfully");
    } else {
        Logger::log("File upload failed: " + message);
    }
}

void MainWindow::updateConnectionStatus(bool online)
{
    if (online) {
        ui->serverConnectionLabel->setText("Server Connection: Online");
    } else {
        ui->serverConnectionLabel->setText("Server Connection: Offline");
    }
}

void MainWindow::on_selectFileButton_clicked()
{
    QString path = QFileDialog::getOpenFileName(
        this,
        tr("Select a file to upload")
        );
    if (path.isEmpty()) return;

    currentUploadPath = path;
    QFileInfo fi(path);
    ui->fileNameLabel->setText(fi.fileName());
    ui->fileTypeLabel->setText(fi.suffix());

    // Read file
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        Logger::log("Cannot open file for preview");
        return;
    }
    QByteArray data = f.readAll();
    f.close();
    currentUploadData = data;

    // Decide preview type
    QMimeDatabase db;
    auto mime = db.mimeTypeForFile(fi);
    if (mime.name().startsWith("text/")) {
        ui->uploadTextPreview->setPlainText(QString::fromUtf8(data));
        ui->uploadPreviewStack->setCurrentIndex(0);
    }
    else if (mime.name().startsWith("image/")) {
        QPixmap pix;
        pix.loadFromData(data);
        ui->uploadImagePreview->setPixmap(pix.scaled(
            ui->uploadImagePreview->size(),
            Qt::KeepAspectRatio,
            Qt::SmoothTransformation));
        ui->uploadPreviewStack->setCurrentIndex(1);
    }
    else {
        ui->uploadTextPreview->setPlainText(tr("No preview available"));
        ui->uploadPreviewStack->setCurrentIndex(0);
    }
}

void MainWindow::on_uploadFileButton_clicked()
{
    if (currentUploadData.isEmpty()) {
        Logger::log("No file selected");
        return;
    }

    // Build Base64 payload (or however your controller expects it)
    QString b64 = QString::fromUtf8(currentUploadData.toBase64());
    authController->uploadFile(b64);
}

// void MainWindow::populateDownloadList(const QStringList &files)
// {
//     ui->downloadFileList->clear();
//     ui->downloadFileList->addItems(files);
//     downloadCache.clear();
// }

void MainWindow::on_downloadFileList_itemSelectionChanged()
{
    auto item = ui->downloadFileList->currentItem();
    if (!item) return;
    QString name = item->text();

    // Assume you’ve already fetched & decrypted it into downloadCache[name]
    QByteArray data = downloadCache.value(name);
    if (data.isEmpty()) {
        Logger::log("No data cached for " + name);
        return;
    }

    ui->downloadFileNameLabel->setText(name);
    QFileInfo fi(name);
    ui->downloadFileTypeLabel->setText(fi.suffix());

    QMimeDatabase db;
    auto mime = db.mimeTypeForFile(fi);

    if (mime.name().startsWith("text/")) {
        ui->downloadTextPreview->setPlainText(QString::fromUtf8(data));
        ui->downloadPreviewStack->setCurrentIndex(0);
    }
    else if (mime.name().startsWith("image/")) {
        QPixmap pix;
        pix.loadFromData(data);
        ui->downloadImagePreview->setPixmap(pix.scaled(
            ui->downloadImagePreview->size(),
            Qt::KeepAspectRatio,
            Qt::SmoothTransformation));
        ui->downloadPreviewStack->setCurrentIndex(1);
    }
    else {
        ui->downloadTextPreview->setPlainText(tr("No preview"));
        ui->downloadPreviewStack->setCurrentIndex(0);
    }
}

void MainWindow::on_downloadFileButton_clicked()
{
    auto item = ui->downloadFileList->currentItem();
    if (!item) return;
    QString name = item->text();
    QByteArray data = downloadCache.value(name);
    if (data.isEmpty()) return;

    QString savePath = QFileDialog::getSaveFileName(
        this,
        tr("Save file as"),
        name
        );
    if (savePath.isEmpty()) return;

    QFile out(savePath);
    if (!out.open(QIODevice::WriteOnly)) {
        Logger::log("Failed to write file");
        return;
    }
    out.write(data);
    out.close();
    Logger::log("Saved " + savePath);
}
