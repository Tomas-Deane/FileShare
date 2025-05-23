
#include "networkmanager.h"
#include "logger.h"
#include <QJsonDocument>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <cstring>

#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

NetworkManager::NetworkManager(QObject *parent)
    : QObject(parent), ssl_ctx(nullptr)
{
#ifdef _WIN32
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        Logger::log(QString("WSAStartup failed: %1").arg(result));
    }
#endif
    initOpenSSL();  // Set up OpenSSL
}

NetworkManager::~NetworkManager()
{
    cleanupOpenSSL();
#ifdef _WIN32
    WSACleanup();
#endif
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
    QJsonObject req;
    req["username"] = username;

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
        emit loginChallenge(
            QByteArray::fromBase64(obj["nonce"].toString().toUtf8()),
            QByteArray::fromBase64(obj["salt"].toString().toUtf8()),
            obj["argon2_opslimit"].toInt(),
            obj["argon2_memlimit"].toInt(),
            QByteArray::fromBase64(obj["encrypted_privkey"].toString().toUtf8()),
            QByteArray::fromBase64(obj["privkey_nonce"].toString().toUtf8())
            );
    } else {
        emit loginResult(false, obj["detail"].toString());
    }
}

void NetworkManager::authenticate(const QString &username, const QByteArray &signature)
{
    QJsonObject req;
    req["username"]  = username;
    req["signature"] = QString::fromUtf8(signature.toBase64());

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

QByteArray NetworkManager::postJson(const QString &host,
                                    quint16 port,
                                    const QString &path,
                                    const QJsonObject &obj,
                                    bool &ok,
                                    QString &message)
{
    ok = false;
    Logger::log(QString("postJson to https://%1:%2%3").arg(host).arg(port).arg(path));

    // DNS lookup
    struct hostent *he = gethostbyname(host.toUtf8().constData());
    if (!he) {
        message = "DNS lookup failed";
        emit networkError(message);
        return {};
    }

#ifdef _WIN32
    SOCKET sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        message = "Socket creation failed";
        emit networkError(message);
        return {};
    }
#else
    int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        message = "Socket creation failed";
        emit networkError(message);
        return {};
    }
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    addr.sin_addr   = *(struct in_addr*)he->h_addr;

    if (::connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
#ifdef _WIN32
        closesocket(sock);
#else
        ::close(sock);
#endif
        message = QString("TCP connect failed to %1:%2").arg(host).arg(port);
        emit networkError(message);
        return {};
    }

    SSL *ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl);
#ifdef _WIN32
        closesocket(sock);
#else
        ::close(sock);
#endif
        message = "SSL handshake failed";
        emit networkError(message);
        return {};
    }

    QByteArray body = QJsonDocument(obj).toJson(QJsonDocument::Compact);
    QByteArray req =
        "POST " + path.toUtf8() + " HTTP/1.1\r\n" +
        "Host: " + host.toUtf8() + "\r\n" +
        "Content-Type: application/json\r\n" +
        "Content-Length: " + QByteArray::number(body.size()) + "\r\n" +
        "Connection: close\r\n\r\n" +
        body;

    SSL_write(ssl, req.constData(), req.size());

    QByteArray resp;
    char buf[4096];
    int len;
    while ((len = SSL_read(ssl, buf, sizeof(buf))) > 0) {
        resp.append(buf, len);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
#ifdef _WIN32
    closesocket(sock);
#else
    ::close(sock);
#endif

    int sep = resp.indexOf("\r\n\r\n");
    if (sep < 0) {
        message = "Invalid HTTP response";
        emit networkError(message);
        return {};
    }

    QByteArray bodyResp = resp.mid(sep + 4);
    message = QString::fromUtf8(bodyResp);
    ok = true;
    return bodyResp;
}
