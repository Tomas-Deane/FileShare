#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <QByteArray>
#include <QString>

class CryptoUtils {
public:
    static QByteArray derivePDK(const QString &password,
                                const QByteArray &salt,
                                quint64 opslimit,
                                quint64 memlimit);

    static void generateKeyPair(QByteArray &publicKey,
                                QByteArray &secretKey);

    static QByteArray encryptSecretKey(const QByteArray &secretKey,
                                       const QByteArray &pdk,
                                       QByteArray &nonce);

    static QByteArray decryptSecretKey(const QByteArray &encryptedSK,
                                       const QByteArray &pdk,
                                       const QByteArray &nonce);

    static QByteArray signMessage(const QByteArray &message,
                                  const QByteArray &secretKey);
};

#endif // CRYPTO_UTILS_H
