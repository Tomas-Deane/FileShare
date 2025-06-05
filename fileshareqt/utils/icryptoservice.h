#ifndef ICRYPTOSERVICE_H
#define ICRYPTOSERVICE_H

#include <QString>
#include <QByteArray>
#include <QDebug>

// pure virtual interface for all crypto operations
class ICryptoService
{

protected:
    // protected member in an inheritance hierarchy (caps the length of random byte generation)
    static const int MAX_RANDOM_LENGTH = 4096;

public:
    // Ctor and Dtor behaviour in an inheritance hierarchy (see derived class in cryptoservice)
    ICryptoService()
    {
        qDebug() << "ICryptoService ctor";
    }
    virtual ~ICryptoService()
    {
        qDebug() << "ICryptoService dtor";
    }

    // default Argon2id parameters (matches libsodiums moderate settings)
    const static quint64 OPSLIMIT_MODERATE = 3;
    const static quint64 MEMLIMIT_MODERATE = 268435456; // 256 MiB

    // Derive a key (e.g. PDK) from password+salt
    virtual QByteArray deriveKey(const QString &password,
                                 const QByteArray &salt,
                                 quint64 opslimit,
                                 quint64 memlimit) = 0;

    // Generate cryptographically secure random bytes
    virtual QByteArray randomBytes(int length) = 0;

    // Generate a signing keypair
    virtual void generateKeyPair(QByteArray &publicKey,
                                 QByteArray &secretKey) = 0;

    // Get a fresh random AEAD key of length 32 bytes
    virtual QByteArray generateAeadKey() = 0;

    // Generate an X25519 keypair (Curve25519) for X3DH identity keys / OPKs
    virtual void generateX25519KeyPair(QByteArray &publicKey,
                               QByteArray &secretKey) = 0;

    // Create a single one‐time pre‐key (Curve25519)
    virtual void generateOneTimePreKey(QByteArray &opkPub,
                               QByteArray &opkPriv) = 0;

    // Compute OOB verification code from two identity‐pubkeys
    virtual QString computeOOBVerificationCode(const QByteArray &ik1_pub,
                                       const QByteArray &ik2_pub) = 0;

    // Symmetric encryption (AEAD)
    virtual QByteArray encrypt(const QByteArray &plaintext,
                               const QByteArray &key,
                               QByteArray &nonce) = 0;

    // Symmetric decryption (AEAD)
    virtual QByteArray decrypt(const QByteArray &ciphertext,
                               const QByteArray &key,
                               const QByteArray &nonce) = 0;

    // Signature generation
    virtual QByteArray sign(const QByteArray &message,
                            const QByteArray &secretKey) = 0;

    // Securely zero-out sensitive data
    virtual void secureZeroMemory(QByteArray &data) = 0;

    // Derive a Curve25519/ECDH shared key from ourPriv + theirPub
    virtual QByteArray deriveSharedKey(const QByteArray &ourPriv,
                                       const QByteArray &theirPub) = 0;

    virtual QByteArray hkdfSha256(const QByteArray &salt,
                                  const QByteArray &ikm,
                                  int outputLength) = 0;

    // Convert an Ed25519 public key (32 bytes) to Curve25519 public key (32 bytes):
    virtual bool ed25519PubKeyToCurve25519(QByteArray &curvePub,
                                   const QByteArray &edPub) = 0;

    // Convert an Ed25519 secret key (64 bytes) to Curve25519 private key (32 bytes):
    virtual bool ed25519PrivKeyToCurve25519(QByteArray &curvePriv,
                                    const QByteArray &edPriv) = 0;

};

#endif // ICRYPTOSERVICE_H
