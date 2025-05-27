#include "passwordstrength.h"
#include <QFile>
#include <QNetworkAccessManager>
#include <QTextStream>
#include <QRegularExpression>
#include <QCryptographicHash>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QObject>
#include <QEventLoop>
#include <QUrl>

PasswordStrength::PasswordStrength()
    : networkManager(new QNetworkAccessManager()) {}

StrengthResult PasswordStrength::evaluate(const QString &password)
{
    int lenScore = scoreLength(password.length());         // up to 40
    int varScore = scoreVariety(password);                 // up to 40

    int raw = lenScore + varScore;
    int score = qBound(0, raw, 100);
    return { score, descForScore(score) };
}

bool PasswordStrength::isAcceptable(const QString &password, QString *reason)
{
    int len = password.length();
    if (len < 8) {
        if (reason) *reason = "Password must be at least 8 characters";
        return false;
    }
    if (len > 64) {
        if (reason) *reason = "Password must be at most 64 characters";
        return false;
    }
    if (isBreached(password, reason)) {
        return false;
    }
    return true;
}

int PasswordStrength::scoreLength(int length)
{
    // 8 → 20, 16 → 40, 32 → 60, 48 → 80, 64 → 100 (capped)
    if (length < 8) return 0;
    double pct = double(length - 8) / double(64 - 8);
    return int(qBound(0.0, pct, 1.0) * 40.0) + 20;
}

int PasswordStrength::scoreVariety(const QString &pw)
{
    bool hasLower = false, hasUpper = false, hasDigit = false, hasSymbol = false, hasUnicode = false;
    for (auto ch : pw) {
        if (ch.isLower()) hasLower = true;
        else if (ch.isUpper()) hasUpper = true;
        else if (ch.isDigit()) hasDigit = true;
        else if (ch.unicode() > 0x7F) hasUnicode = true;
        else hasSymbol = true;
    }
    int classes = hasLower + hasUpper + hasDigit + hasSymbol + hasUnicode;
    // Up to 5 classes → evenly distributed over 40 points
    return int(double(classes) / 5.0 * 40.0);
}

QString PasswordStrength::descForScore(int score)
{
    if (score < 30)       return "Too weak";
    else if (score < 50)  return "Weak";
    else if (score < 70)  return "Moderate";
    else if (score < 90)  return "Strong";
    else                  return "Very strong";
}

bool PasswordStrength::isBreached(const QString &password, QString *reason)
{
    // 1. SHA-1 the UTF-8 password, uppercase hex
    QByteArray hash = QCryptographicHash::hash(password.toUtf8(), QCryptographicHash::Sha1)
                          .toHex().toUpper();
    QString prefix = QString::fromUtf8(hash.left(5));
    QByteArray suffix = hash.mid(5);

    // 2. Query the HIBP range API
    QNetworkRequest req(QUrl("https://api.pwnedpasswords.com/range/" + prefix));
    req.setHeader(QNetworkRequest::UserAgentHeader, "FileShareQt");
    QNetworkReply *reply = networkManager->get(req);

    // 3. Wait synchronously (blocking) for-demo; you can make this async if you like
    QEventLoop loop;
    QObject::connect(
        reply, &QNetworkReply::finished,
        &loop,  &QEventLoop::quit
    );
    loop.exec();

    if (reply->error() != QNetworkReply::NoError) {
        // on network error, choose to allow or reject; here we *allow* but log
        qWarning() << "HIBP lookup failed:" << reply->errorString();
        reply->deleteLater();
        return false;
    }

    // 4. Parse lines “<suffix>:<count>\r\n…”
    const QByteArray body = reply->readAll();
    reply->deleteLater();
    for (auto line : body.split('\n')) {
        auto parts = line.trimmed().split(':');
        if (parts.size() < 2) continue;
        if (parts[0] == suffix) {
            if (reason) *reason =
                    QString("Password found %1 times in breaches").arg(QString(parts[1]));
            return true;
        }
    }
    return false;
}
