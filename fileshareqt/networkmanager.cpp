// File: fileshareqt/networkmanager.cpp
#include "networkmanager.h"
#include "logger.h"
#include <QJsonDocument>

NetworkManager::NetworkManager(QObject *parent)
    : QObject(parent)
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

/// Centralized TCP+SSL connect + handshake
SSL *NetworkManager::openSslConnection(const QString &host,
                                       quint16 port,
                                       int &sockOut,
                                       QString &errorMsg)
{
    // DNS lookup
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

    // TCP connect
    int sock = -1;
    for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) continue;
        if (::connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);

    if (sock < 0) {
        errorMsg = QString("Could not connect to %1:%2").arg(host).arg(port);
        emit connectionStatusChanged(false);
        return nullptr;
    }

    // SSL handshake
    SSL *ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl);
        close(sock);
        errorMsg = "SSL handshake failed";
        emit connectionStatusChanged(false);
        return nullptr;
    }

    // success!
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
    Logger::log(QString("postJson to https://%1:%2%3")
                    .arg(host).arg(port).arg(path));

    int sock = -1;
    QString err;
    SSL *ssl = openSslConnection(host, port, sock, err);
    if (!ssl) {
        emit networkError(err);
        return {};
    }

    // build request
    QByteArray body = QJsonDocument(obj).toJson(QJsonDocument::Compact);
    QByteArray req =
        "POST " + path.toUtf8() + " HTTP/1.1\r\n"
                                  "Host: " + host.toUtf8() + "\r\n"
                          "Content-Type: application/json\r\n"
                          "Content-Length: " + QByteArray::number(body.size()) + "\r\n"
                                            "Connection: close\r\n\r\n" +
        body;

    if (SSL_write(ssl, req.constData(), req.size()) <= 0) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
        message = "Failed to send HTTP request";
        emit connectionStatusChanged(false);
        emit networkError(message);
        return {};
    }

    // read response
    QByteArray resp;
    char buf[4096];
    int len;
    while ((len = SSL_read(ssl, buf, sizeof(buf))) > 0) {
        resp.append(buf, len);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);

    // parse HTTP
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
    QByteArray resp = postJson("gobbler.info", 3210, "/signup", payload, ok, message);

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
    QByteArray resp = postJson("gobbler.info", 3210, "/login", req, ok, message);

    Logger::log("Received login response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit loginResult(false, message);
        return;
    }

    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "challenge") {
        QByteArray nonce = QByteArray::fromBase64(obj["nonce"].toString().toUtf8());
        QByteArray salt = QByteArray::fromBase64(obj["salt"].toString().toUtf8());
        QByteArray encryptedPrivKey = QByteArray::fromBase64(obj["encrypted_privkey"].toString().toUtf8());
        QByteArray privKeyNonce   = QByteArray::fromBase64(obj["privkey_nonce"].toString().toUtf8());
        QByteArray encryptedKek    = QByteArray::fromBase64(obj["encrypted_kek"].toString().toUtf8());
        QByteArray kekNonce        = QByteArray::fromBase64(obj["kek_nonce"].toString().toUtf8());
        int opslimit = obj["argon2_opslimit"].toInt();
        int memlimit = obj["argon2_memlimit"].toInt();
        emit loginChallenge(nonce, salt, opslimit, memlimit,
                            encryptedPrivKey, privKeyNonce,
                            encryptedKek, kekNonce);
    } else {
        emit loginResult(false, obj["detail"].toString());
    }
}

void NetworkManager::requestChallenge(const QString &username,
                                      const QString &operation)
{
    QJsonObject req{
        {"username", username},
        {"operation", operation}
    };
    Logger::log(QString("Requesting challenge for '%1' op='%2'")
                    .arg(username).arg(operation));
    Logger::log("Challenge request payload: " +
                QString::fromUtf8(QJsonDocument(req).toJson(QJsonDocument::Compact)));

    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3210, "/challenge", req, ok, message);

    Logger::log("Received challenge response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit networkError(message);
        return;
    }

    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "challenge") {
        QByteArray nonce = QByteArray::fromBase64(obj["nonce"].toString().toUtf8());
        emit challengeResult(nonce, operation);
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
    QByteArray resp = postJson("gobbler.info", 3210, "/authenticate", req, ok, message);

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
    QByteArray resp = postJson("gobbler.info", 3210, "/change_username", payload, ok, message);
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
    QByteArray resp = postJson("gobbler.info", 3210, "/change_password", payload, ok, message);
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
    Logger::log("Sending uploadFile request: " +
                QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact)));
    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3210, "/upload_file", payload, ok, message);
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

void NetworkManager::checkConnection()
{
    int sock = -1;
    QString error;
    SSL *ssl = openSslConnection("gobbler.info", 3210, sock, error);
    if (!ssl) {
        return;
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
}
