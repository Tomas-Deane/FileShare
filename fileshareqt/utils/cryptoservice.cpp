#include "cryptoservice.h"
#include "crypto_utils.h"

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
    // If the caller requests more than MAX_RANDOM_LENGTH, clamp it
    int reqLen = length;
    if (length > ICryptoService::MAX_RANDOM_LENGTH) {
        reqLen = ICryptoService::MAX_RANDOM_LENGTH;
    }
    return CryptoUtils::randomBytes(reqLen);
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

void CryptoService::generateX25519KeyPair(QByteArray &publicKey,
                                          QByteArray &secretKey)
{
    CryptoUtils::generateX25519KeyPair(publicKey, secretKey);
}

void CryptoService::generateOneTimePreKey(QByteArray &opkPub,
                                          QByteArray &opkPriv)
{
    CryptoUtils::generateOneTimePreKey(opkPub, opkPriv);
}

QString CryptoService::computeOOBVerificationCode(const QByteArray &ik1_pub,
                                                  const QByteArray &ik2_pub)
{
    return CryptoUtils::computeOOBCode(ik1_pub, ik2_pub);
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

QByteArray CryptoService::deriveSharedKey(const QByteArray &ourPriv,
                                          const QByteArray &theirPub)
{
    return CryptoUtils::computeSharedKey(ourPriv, theirPub);
}

QByteArray CryptoService::hkdfSha256(const QByteArray &salt,
                                     const QByteArray &ikm,
                                     int outputLength)
{
    return CryptoUtils::hkdfSha256(salt, ikm, outputLength);
}

void CryptoService::secureZeroMemory(QByteArray &data)
{
    CryptoUtils::secureZeroMemory(data);
}
