#include "networkmanager.h"
#include "logger.h"

#include <QJsonDocument>
#include <QJsonArray>
#include <QStringList>

// POSIX sockets
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

NetworkManager::NetworkManager(QObject *parent)
    : INetworkManager(parent)
    , ssl_ctx(nullptr)
{
    initOpenSSL();
}

NetworkManager::~NetworkManager()
{
    cleanupOpenSSL();
}

void NetworkManager::initOpenSSL()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        Logger::log("Failed to create SSL_CTX");
    }
}

void NetworkManager::cleanupOpenSSL()
{
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = nullptr;
    }
    EVP_cleanup();
}

SSL *NetworkManager::openSslConnection(const QString &host,
                                       quint16 port,
                                       int &sockOut,
                                       QString &errorMsg)
{
    struct addrinfo hints = {};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo *res = nullptr;
    int gai_err = getaddrinfo(host.toUtf8().constData(),
                              QByteArray::number(port).constData(),
                              &hints, &res);
    if (gai_err != 0) {
        errorMsg = QString("DNS lookup failed: %1").arg(gai_strerror(gai_err));
        emit connectionStatusChanged(false);
        return nullptr;
    }

    int sock = -1;
    for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) continue;
        if (::connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) break;
        ::close(sock);
        sock = -1;
    }
    freeaddrinfo(res);

    if (sock < 0) {
        errorMsg = QString("Could not connect to %1:%2").arg(host).arg(port);
        emit connectionStatusChanged(false);
        return nullptr;
    }

    SSL *ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl);
        ::close(sock);
        errorMsg = "SSL handshake failed";
        emit connectionStatusChanged(false);
        return nullptr;
    }

    sockOut = sock;
    emit connectionStatusChanged(true);
    return ssl;
}

QByteArray NetworkManager::postJson(const QString &host,
                                    quint16 port,
                                    const QString &path,
                                    const QJsonObject &obj,
                                    bool &ok,
                                    QString &message)
{
    ok = false;
    Logger::log(QString("postJson to https://%1:%2%3").arg(host).arg(port).arg(path));

    int sock = -1;
    QString err;
    SSL *ssl = openSslConnection(host, port, sock, err);
    if (!ssl) {
        emit networkError(err);
        return {};
    }

    QByteArray body = QJsonDocument(obj).toJson(QJsonDocument::Compact);
    QByteArray req =
        "POST " + path.toUtf8() + " HTTP/1.1\r\n"
                                  "Host: " + host.toUtf8() + "\r\n"
                          "Content-Type: application/json\r\n"
                          "Content-Length: " + QByteArray::number(body.size()) + "\r\n"
                                            "Connection: close\r\n\r\n" + body;

    if (SSL_write(ssl, req.constData(), req.size()) <= 0) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ::close(sock);
        message = "Failed to send HTTP request";
        emit connectionStatusChanged(false);
        emit networkError(message);
        return {};
    }

    QByteArray resp;
    char buf[4096];
    int len;
    while ((len = SSL_read(ssl, buf, sizeof(buf))) > 0) {
        resp.append(buf, len);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    ::close(sock);

    int header_end = resp.indexOf("\r\n\r\n");
    if (header_end < 0) {
        message = "Invalid HTTP response";
        emit networkError(message);
        return {};
    }

    QByteArray header = resp.left(header_end);
    QList<QByteArray> lines = header.split('\n');
    QStringList parts = QString::fromUtf8(lines[0].trimmed()).split(' ');
    int statusCode = parts.size() > 1 ? parts[1].toInt() : -1;
    QByteArray bodyResp = resp.mid(header_end + 4);

    if (statusCode < 200 || statusCode >= 300) {
        QJsonDocument j = QJsonDocument::fromJson(bodyResp);
        if (j.isObject() && j.object().contains("detail")) {
            message = j.object().value("detail").toString();
        } else {
            message = QString("HTTP error %1").arg(statusCode);
        }
        return {};
    }

    ok = true;
    message = QString::fromUtf8(bodyResp);
    return bodyResp;
}

void NetworkManager::signup(const QJsonObject &payload)
{
    Logger::log("Sending signup request: " +
                QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact)));

    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3220, "/signup", payload, ok, message);

    Logger::log("Received signup response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit signupResult(false, message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        emit signupResult(true, obj["status"].toString());
    } else {
        emit signupResult(false, obj["detail"].toString());
    }
}

void NetworkManager::login(const QString &username)
{
    QJsonObject req{{"username", username}};
    Logger::log("Sending login request for user '" + username + "'");
    Logger::log("Login request payload: " +
                QString::fromUtf8(QJsonDocument(req).toJson(QJsonDocument::Compact)));

    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3220, "/login", req, ok, message);

    Logger::log("Received login response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit loginResult(false, message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "challenge") {
        emit loginChallenge(
            QByteArray::fromBase64(obj["nonce"].toString().toUtf8()),
            QByteArray::fromBase64(obj["salt"].toString().toUtf8()),
            obj["argon2_opslimit"].toInt(),
            obj["argon2_memlimit"].toInt(),
            QByteArray::fromBase64(obj["encrypted_privkey"].toString().toUtf8()),
            QByteArray::fromBase64(obj["privkey_nonce"].toString().toUtf8()),
            QByteArray::fromBase64(obj["encrypted_kek"].toString().toUtf8()),
            QByteArray::fromBase64(obj["kek_nonce"].toString().toUtf8())
            );
    } else {
        emit loginResult(false, obj["detail"].toString());
    }
}

void NetworkManager::requestChallenge(const QString &username,
                                      const QString &operation)
{
    QJsonObject req{{"username", username}, {"operation", operation}};
    Logger::log(QString("Requesting challenge for '%1' op='%2'")
                    .arg(username).arg(operation));
    Logger::log("Challenge request payload: " +
                QString::fromUtf8(QJsonDocument(req).toJson(QJsonDocument::Compact)));

    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3220, "/challenge", req, ok, message);

    Logger::log("Received challenge response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit networkError(message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "challenge") {
        emit challengeResult(
            QByteArray::fromBase64(obj["nonce"].toString().toUtf8()),
            operation
            );
    } else {
        emit networkError(obj["detail"].toString());
    }
}

void NetworkManager::authenticate(const QString &username,
                                  const QByteArray &nonce,
                                  const QByteArray &signature)
{
    QJsonObject req{
        {"username", username},
        {"nonce", QString::fromUtf8(nonce.toBase64())},
        {"signature", QString::fromUtf8(signature.toBase64())}
    };
    Logger::log("Sending authenticate request for user '" + username + "'");
    Logger::log("Authenticate request payload: " +
                QString::fromUtf8(QJsonDocument(req).toJson(QJsonDocument::Compact)));

    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3220, "/authenticate", req, ok, message);

    Logger::log("Received authenticate response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit loginResult(false, message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        emit loginResult(true, obj["message"].toString());
    } else {
        emit loginResult(false, obj["detail"].toString());
    }
}

void NetworkManager::changeUsername(const QJsonObject &payload)
{
    Logger::log("Sending changeUsername request: " +
                QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact)));

    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3220, "/change_username", payload, ok, message);
    Logger::log("Received changeUsername response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit changeUsernameResult(false, message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        emit changeUsernameResult(true, obj["message"].toString());
    } else {
        emit changeUsernameResult(false, obj["detail"].toString());
    }
}

void NetworkManager::changePassword(const QJsonObject &payload)
{
    Logger::log("Sending changePassword request: " +
                QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact)));

    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3220, "/change_password", payload, ok, message);
    Logger::log("Received changePassword response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit changePasswordResult(false, message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        emit changePasswordResult(true, obj["message"].toString());
    } else {
        emit changePasswordResult(false, obj["detail"].toString());
    }
}

void NetworkManager::uploadFile(const QJsonObject &payload)
{
    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3220, "/upload_file", payload, ok, message);
    Logger::log("Received uploadFile response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit uploadFileResult(false, message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        emit uploadFileResult(true, obj["message"].toString());
    } else {
        emit uploadFileResult(false, obj["detail"].toString());
    }
}

void NetworkManager::listFiles(const QJsonObject &payload)
{
    Logger::log("Sending listFiles request: " +
                QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact)));
    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3220, "/list_files", payload, ok, message);
    Logger::log("Received listFiles response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit listFilesResult(false, QList<FileEntry>(), message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        QJsonArray arr = obj["files"].toArray();
        QList<FileEntry> fileList;
        fileList.reserve(arr.size());
        for (const QJsonValue &v : arr) {
            if (!v.isObject()) continue;
            QJsonObject fileObj = v.toObject();
            FileEntry fe;
            fe.filename = fileObj.value("filename").toString();
            // “id” comes from the server’s JSON; it should always exist
            fe.id = static_cast<qint64>( fileObj.value("id").toInt() );
            fileList.append(fe);
        }
        emit listFilesResult(true, fileList, QString());
    }
}

void NetworkManager::downloadFile(const QJsonObject &payload)
{
    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3220, "/download_file", payload, ok, message);
    if (!ok) {
        emit downloadFileResult(false, QString(), QString(), QString(), QString(), message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        emit downloadFileResult(
            true,
            obj["encrypted_file"].toString(),
            obj["file_nonce"].toString(),
            obj["encrypted_dek"].toString(),
            obj["dek_nonce"].toString(),
            QString()
            );
    } else {
        emit downloadFileResult(false, QString(), QString(), QString(), QString(), obj["detail"].toString());
    }
}

void NetworkManager::deleteFile(const QJsonObject &payload)
{
    Logger::log("Sending deleteFile request: " +
                QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact)));
    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3220, "/delete_file", payload, ok, message);
    Logger::log("Received deleteFile response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit deleteFileResult(false, message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        emit deleteFileResult(true, obj["message"].toString());
    } else {
        emit deleteFileResult(false, obj["detail"].toString());
    }
}

void NetworkManager::retrieveFileDEK(const QJsonObject &payload)
{
    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3220, "/retrieve_file_dek", payload, ok, message);
    Logger::log("Received retrieveFileDEK response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit retrieveFileDEKResult(false, QString(), QString(), message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        emit retrieveFileDEKResult(
            true,
            obj.value("encrypted_dek").toString(),
            obj.value("dek_nonce").toString(),
            QString()
            );
    } else {
        emit retrieveFileDEKResult(false, QString(), QString(), obj.value("detail").toString());
    }
}

void NetworkManager::getPreKeyBundle(const QJsonObject &payload)
{
    Logger::log("Sending getPreKeyBundle request: " +
                QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact)));

    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3220, "/get_pre_key_bundle", payload, ok, message);
    Logger::log("Received getPreKeyBundle response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit getPreKeyBundleResult(false, "", "", "", message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        QJsonObject bundle = obj["prekey_bundle"].toObject();
        QString ik_pub     = bundle["IK_pub"].toString();
        QString spk_pub    = bundle["SPK_pub"].toString();
        QString spk_sig    = bundle["SPK_signature"].toString();
        emit getPreKeyBundleResult(true, ik_pub, spk_pub, spk_sig, "");
    } else {
        emit getPreKeyBundleResult(false, "", "", "", obj["detail"].toString());
    }
}

void NetworkManager::backupTOFU(const QJsonObject &payload)
{
    Logger::log("Sending backupTOFU request: " +
                QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact)));

    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3220, "/backup_tofu", payload, ok, message);
    Logger::log("Received backupTOFU response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit backupTOFUResult(false, message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj.contains("status") && obj["status"].toString() == "ok") {
        emit backupTOFUResult(true, obj["message"].toString());
    } else {
        emit backupTOFUResult(false, obj["detail"].toString());
    }
}

void NetworkManager::getBackupTOFU(const QJsonObject &payload)
{
    Logger::log("Sending getBackupTOFU request: " +
                QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact)));

    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3220, "/get_backup_tofu", payload, ok, message);
    Logger::log("Received getBackupTOFU response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit getBackupTOFUResult(false, "", "", message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        QString enc      = obj["encrypted_backup"].toString();
        QString nonce    = obj["backup_nonce"].toString();
        emit getBackupTOFUResult(true, enc, nonce, "");
    } else {
        emit getBackupTOFUResult(false, "", "", obj["detail"].toString());
    }
}

// ─── /share_file ─────────────────────────────────────────────────────────────
void NetworkManager::shareFile(const QJsonObject &payload)
{
    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3220, "/share_file", payload, ok, message);
    Logger::log("Received shareFile response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit shareFileResult(false, message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        emit shareFileResult(true, obj.value("message").toString());
    } else {
        emit shareFileResult(false, obj.value("detail").toString());
    }
}

// ─── /list_shared_to ─────────────────────────────────────────────────────────
void NetworkManager::listSharedTo(const QJsonObject &payload)
{
    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3220, "/list_shared_to", payload, ok, message);
    Logger::log("Received listSharedTo response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit listSharedToResult(false, QJsonArray(), message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        QJsonArray arr = obj.value("shares").toArray();
        emit listSharedToResult(true, arr, QString());
    } else {
        emit listSharedToResult(false, QJsonArray(), obj.value("detail").toString());
    }
}

// ─── /list_shared_from ───────────────────────────────────────────────────────
void NetworkManager::listSharedFrom(const QJsonObject &payload)
{
    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3220, "/list_shared_from", payload, ok, message);
    Logger::log("Received listSharedFrom response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit listSharedFromResult(false, QJsonArray(), message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        QJsonArray arr = obj.value("shares").toArray();
        emit listSharedFromResult(true, arr, QString());
    } else {
        emit listSharedFromResult(false, QJsonArray(), obj.value("detail").toString());
    }
}

// ─── /list_sharers ─────────────────────────────────────────────────────────
void NetworkManager::listSharers(const QJsonObject &payload)
{
    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3220, "/list_sharers", payload, ok, message);
    Logger::log("Received listSharers response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit listSharersResult(false, QStringList(), message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        // Expect: { "status":"ok", "usernames":[ "alice", "bob", … ] }
        QStringList users;
        for (const QJsonValue &v : obj["usernames"].toArray())
            users.append(v.toString());
        emit listSharersResult(true, users, QString());
    } else {
        emit listSharersResult(false, QStringList(), obj["detail"].toString());
    }
}

void NetworkManager::getOPK(const QJsonObject &payload)
{
    Logger::log("Sending getOPK request: " +
                QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact)));

    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3220, "/opk", payload, ok, message);
    Logger::log("Received getOPK response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit getOPKResult(false, 0, QString(), message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        int opk_id = obj["opk_id"].toInt();
        QString pre_key_b64 = obj["pre_key"].toString();
        emit getOPKResult(true, opk_id, pre_key_b64, QString());
    } else {
        emit getOPKResult(false, 0, QString(), obj["detail"].toString());
    }
}

void NetworkManager::downloadSharedFile(const QJsonObject &payload)
{
    bool ok = false;
    QString message;
    // POST to /download_shared_file exactly as you do for downloadFile:
    QByteArray resp = postJson("gobbler.info", 3220, "/download_shared_file", payload, ok, message);

    if (!ok) {
        // Failed HTTP or JSON parse → emit all‐empty fields + error
        emit downloadSharedFileResult(false,
                                      QString(),
                                      QString(),
                                      QString(),
                                      QString(),
                                      QString(),
                                      QString(),
                                      QString(),
                                      QString(),
                                      0,
                                      message);
        return;
    }

    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        emit downloadSharedFileResult(
            true,
            obj["encrypted_file"].toString(),
            obj["file_nonce"].toString(),
            obj["encrypted_file_key"].toString(),
            obj["file_key_nonce"].toString(),
            obj["EK_pub"].toString(),
            obj["IK_pub"].toString(),
            obj["SPK_pub"].toString(),
            obj["SPK_signature"].toString(),
            obj["opk_id"].toInt(),
            QString()
            );
    } else {
        emit downloadSharedFileResult(false,
                                      QString(),
                                      QString(),
                                      QString(),
                                      QString(),
                                      QString(),
                                      QString(),
                                      QString(),
                                      QString(),
                                      0,
                                      obj["detail"].toString());
    }
}

void NetworkManager::checkConnection()
{
    int sock = -1;
    QString error;
    SSL *ssl = openSslConnection("gobbler.info", 3220, sock, error);
    if (!ssl) return;
    SSL_shutdown(ssl);
    SSL_free(ssl);
    ::close(sock);
}
