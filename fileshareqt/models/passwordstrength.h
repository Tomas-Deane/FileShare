#ifndef PASSWORDSTRENGTH_H
#define PASSWORDSTRENGTH_H

#include <QString>
// forward-declare the class you use a pointer to:
class QNetworkAccessManager;

struct StrengthResult {
    int score;             // 0–100
    QString description;   // Too weak, Weak, Moderate, Strong, Very strong
};

class PasswordStrength
{
public:
    PasswordStrength();

    // Returns strength result; always between 0–100
    StrengthResult evaluate(const QString &password);

    // Returns true if password meets OWASP-enforced minimums
    bool isAcceptable(const QString &password, QString *reason = nullptr);

    // Returns true if the password appears in a breach per HIBP
    bool isBreached(const QString &password, QString *reason = nullptr);

private:
    QNetworkAccessManager *networkManager;

    int scoreLength(int length);
    int scoreVariety(const QString &pw);
    QString descForScore(int score);
};

#endif // PASSWORDSTRENGTH_H
