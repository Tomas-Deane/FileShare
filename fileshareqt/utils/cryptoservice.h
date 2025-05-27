#ifndef CRYPTOSERVICE_H
#define CRYPTOSERVICE_H

#include "icryptoservice.h"

// Concrete implementation of ICryptoService using CryptoUtils.
class CryptoService : public ICryptoService
{
public:
    QByteArray deriveKey(const QString &password,
                         const QByteArray &salt,
                         quint64 opslimit,
                         quint64 memlimit) override;

    void generateKeyPair(QByteArray &publicKey,
                         QByteArray &secretKey) override;

    QByteArray encrypt(const QByteArray &plaintext,
                       const QByteArray &key,
                       QByteArray &nonce) override;

    QByteArray decrypt(const QByteArray &ciphertext,
                       const QByteArray &key,
                       const QByteArray &nonce) override;

    QByteArray sign(const QByteArray &message,
                    const QByteArray &secretKey) override;
};

#endif // CRYPTOSERVICE_H
