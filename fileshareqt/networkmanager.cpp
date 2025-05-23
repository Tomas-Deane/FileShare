
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
    initOpenSSL();  // set up OpenSSL
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

    struct addrinfo hints{};
    struct addrinfo *res = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    QByteArray portStr = QByteArray::number(port);
    int gai_err = getaddrinfo(host.toUtf8().constData(), portStr.constData(), &hints, &res);
    if (gai_err != 0) {
        message = QString("DNS lookup failed: %1").arg(gai_strerror(gai_err));
        emit networkError(message);
        return {};
    }

    int sock = -1;
    for (struct addrinfo *rp = res; rp != nullptr; rp = rp->ai_next) {
#ifdef _WIN32
        sock = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == INVALID_SOCKET) continue;
#else
        sock = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) continue;
#endif

        if (::connect(sock, rp->ai_addr, static_cast<int>(rp->ai_addrlen)) == 0) {
            break;  // success
        }

#ifdef _WIN32
        closesocket(sock);
#else
        ::close(sock);
#endif
        sock = -1;
    }
    freeaddrinfo(res);

    if (sock < 0) {
        message = QString("Could not connect to %1:%2").arg(host).arg(port);
        emit networkError(message);
        return {};
    }

    // ssl handshake
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

    // build and send http request
    QByteArray body = QJsonDocument(obj).toJson(QJsonDocument::Compact);
    QByteArray req =
        "POST " + path.toUtf8() + " HTTP/1.1\r\n"
                                  "Host: " + host.toUtf8() + "\r\n"
                          "Content-Type: application/json\r\n"
                          "Content-Length: " + QByteArray::number(body.size()) + "\r\n"
                                            "Connection: close\r\n\r\n" +
        body;

    if (SSL_write(ssl, req.constData(), static_cast<int>(req.size())) <= 0) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
#ifdef _WIN32
        closesocket(sock);
#else
        ::close(sock);
#endif
        message = "Failed to send HTTP request";
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
#ifdef _WIN32
    closesocket(sock);
#else
    ::close(sock);
#endif

    // parse http status
    int header_end = resp.indexOf("\r\n\r\n");
    if (header_end < 0) {
        message = "Invalid HTTP response";
        emit networkError(message);
        return {};
    }

    QByteArray header = resp.left(header_end);
    // extract first line
    QList<QByteArray> headerLines = header.split('\n');
    QString statusLine = QString::fromUtf8(headerLines.value(0).trimmed());
    QStringList statusParts = statusLine.split(' ');
    int statusCode = statusParts.size() > 1 ? statusParts.at(1).toInt() : -1;

    QByteArray bodyResp = resp.mid(header_end + 4);
    if (statusCode < 200 || statusCode >= 300) {
        // try to extract JSON "detail" field, otherwise fallback to code
        QJsonDocument json = QJsonDocument::fromJson(bodyResp);
        QString detail;
        if (json.isObject() && json.object().contains("detail")) {
            detail = json.object().value("detail").toString();
        }
        message = detail.isEmpty()
                      ? QString("HTTP error %1").arg(statusCode)
                      : detail;
        return {};
    }

    // success
    ok = true;
    message = QString::fromUtf8(bodyResp);
    return bodyResp;
}
