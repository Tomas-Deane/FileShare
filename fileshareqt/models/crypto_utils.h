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

    /// Generate a new X25519 keypair (Curve25519) for X3DH (32‐byte public and secret).
    static void generateX25519KeyPair(QByteArray &publicKey,
                                      QByteArray &secretKey);

    /// Create one “one‐time pre‐key” (Curve25519) – same as generateX25519KeyPair().
    static void generateOneTimePreKey(QByteArray &opkPub,
                                      QByteArray &opkPriv);

    /// Compute the 60‐hex‐character OOB verification code from two IK_pubs:
    ///   sort them (bytewise), concat, SHA‐256, hex, truncate(60).
    static QString computeOOBCode(const QByteArray &ik1_pub,
                                  const QByteArray &ik2_pub);

    /// Generate an AEAD key for file encryption or KEK (32 bytes).
    static QByteArray generateAeadKey();

    /// Ed25519 keypair
    static void generateKeyPair(QByteArray &publicKey,
                                QByteArray &secretKey);

    /// AEAD encrypt a secret‐key under PDK
    static QByteArray encryptSecretKey(const QByteArray &secretKey,
                                       const QByteArray &pdk,
                                       QByteArray &nonce);

    /// AEAD decrypt a secret‐key under PDK
    static QByteArray decryptSecretKey(const QByteArray &encryptedSK,
                                       const QByteArray &pdk,
                                       const QByteArray &nonce);

    /// Ed25519 signature
    static QByteArray signMessage(const QByteArray &message,
                                  const QByteArray &secretKey);

    // Securely zero and clear memory (uses sodium_memzero)
    static void secureZeroMemory(QByteArray &data);

    // perform a Curve25519 ECDH (crypto_scalarmult)
    static QByteArray computeSharedKey(const QByteArray &ourPriv,
                                       const QByteArray &theirPub);

    static QByteArray hkdfSha256(const QByteArray &salt,
                                 const QByteArray &ikm,
                                 int outputLength);
};

#endif // CRYPTO_UTILS_H
