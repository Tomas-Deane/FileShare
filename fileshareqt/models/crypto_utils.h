#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <QByteArray>
#include <QString>

class CryptoUtils {
public:
    /// call once at startup
    static void initializeLibrary();

    /// Argon2id key derivation
    static QByteArray derivePDK(const QString &password,
                                const QByteArray &salt,
                                quint64 opslimit,
                                quint64 memlimit);

    /// secure random bytes
    static QByteArray randomBytes(int length);


    static QByteArray generateAeadKey();

    /// Ed25519 keypair
    static void generateKeyPair(QByteArray &publicKey,
                                QByteArray &secretKey);

    /// AEAD encrypt a secret-key under PDK
    static QByteArray encryptSecretKey(const QByteArray &secretKey,
                                       const QByteArray &pdk,
                                       QByteArray &nonce);

    /// AEAD decrypt a secret-key under PDK
    static QByteArray decryptSecretKey(const QByteArray &encryptedSK,
                                       const QByteArray &pdk,
                                       const QByteArray &nonce);

    /// Ed25519 signature
    static QByteArray signMessage(const QByteArray &message,
                                  const QByteArray &secretKey);

};

#endif // CRYPTO_UTILS_H
