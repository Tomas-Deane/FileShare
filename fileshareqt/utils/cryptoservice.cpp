#include "cryptoservice.h"
#include "crypto_utils.h"

#include <QDebug>

CryptoService::CryptoService()
{
    CryptoUtils::initializeLibrary();
}

QByteArray CryptoService::deriveKey(const QString &password,
                                    const QByteArray &salt,
                                    quint64 opslimit,
                                    quint64 memlimit)
{
    return CryptoUtils::derivePDK(password, salt, opslimit, memlimit);
}

QByteArray CryptoService::randomBytes(int length)
{
    return CryptoUtils::randomBytes(length);
}

void CryptoService::generateKeyPair(QByteArray &publicKey,
                                    QByteArray &secretKey)
{
    CryptoUtils::generateKeyPair(publicKey, secretKey);
}

QByteArray CryptoService::generateAeadKey()
{
    return CryptoUtils::generateAeadKey();
}

QByteArray CryptoService::encrypt(const QByteArray &plaintext,
                                  const QByteArray &key,
                                  QByteArray &nonce)
{
    return CryptoUtils::encryptSecretKey(plaintext, key, nonce);
}

QByteArray CryptoService::decrypt(const QByteArray &ciphertext,
                                  const QByteArray &key,
                                  const QByteArray &nonce)
{
    return CryptoUtils::decryptSecretKey(ciphertext, key, nonce);
}

QByteArray CryptoService::sign(const QByteArray &message,
                               const QByteArray &secretKey)
{
    return CryptoUtils::signMessage(message, secretKey);
}
