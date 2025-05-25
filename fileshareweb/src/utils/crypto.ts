import { generateKeyPair as generateEd25519KeyPair, sign as signEd25519 } from '@stablelib/ed25519';

// TypeScript module declaration
declare global {
  interface Window {
    crypto: Crypto;
  }
}

// Export the module
export {};

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface EncryptedPrivateKey {
  encryptedPrivateKey: Uint8Array;
  nonce: Uint8Array;
}

export class CryptoError extends Error {
  constructor(message: string, public cause?: any) {
    super(message);
    this.name = 'CryptoError';
  }
}

// Check if Web Crypto API is available
export async function checkWebCryptoSupport(): Promise<boolean> {
  return window.crypto && window.crypto.subtle !== undefined;
}

// Check if ECDH is supported
export async function checkECDHSupport(): Promise<boolean> {
  try {
    await window.crypto.subtle.generateKey(
      {
        name: "ECDH",
        namedCurve: "P-256"
      },
      true,
      ["deriveKey", "deriveBits"]
    );
    return true;
  } catch {
    return false;
  }
}

export async function generateKeyPair(): Promise<KeyPair> {
  try {
    // Generate Ed25519 key pair using the polyfill
    const { publicKey, secretKey } = generateEd25519KeyPair();
    
    return {
      publicKey: publicKey,
      privateKey: secretKey
    };
  } catch (error) {
    console.error('Key generation error:', error);
    throw new CryptoError("Failed to generate key pair", error);
  }
}

export async function generateSalt(): Promise<Uint8Array> {
  try {
    return window.crypto.getRandomValues(new Uint8Array(32));
  } catch (error) {
    throw new CryptoError("Failed to generate salt", error);
  }
}

export async function encryptPrivateKey(
  privateKey: Uint8Array,
  password: string,
  salt: Uint8Array,
  nonce: Uint8Array,
  opsLimit: number = 3,
  memLimit: number = 67108864
): Promise<EncryptedPrivateKey> {
  try {
    console.log('Encrypting private key with parameters:', {
      privateKeyLength: privateKey.length,
      passwordLength: password.length,
      saltLength: salt.length,
      nonceLength: nonce.length,
      opsLimit,
      memLimit
    });

    // Derive encryption key from password
    const passwordKey = await window.crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits", "deriveKey"]
    );

    const derivedKey = await window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: opsLimit,
        hash: "SHA-256"
      },
      passwordKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"]
    );

    // Encrypt the private key
    const encryptedPrivateKey = await window.crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: nonce
      },
      derivedKey,
      privateKey
    );

    console.log('Private key encrypted successfully');
    return {
      encryptedPrivateKey: new Uint8Array(encryptedPrivateKey),
      nonce: nonce
    };
  } catch (error) {
    console.error('Encryption error:', error);
    throw new CryptoError("Failed to encrypt private key", error);
  }
}

export async function decryptPrivateKey(
  encryptedPrivateKey: Uint8Array,
  password: string,
  salt: Uint8Array,
  nonce: Uint8Array,
  opsLimit: number,
  memLimit: number
): Promise<Uint8Array> {
  try {
    console.log('Decrypting private key with parameters:', {
      encryptedKeyLength: encryptedPrivateKey.length,
      passwordLength: password.length,
      saltLength: salt.length,
      nonceLength: nonce.length,
      opsLimit,
      memLimit
    });

    // Derive decryption key from password
    const passwordKey = await window.crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits", "deriveKey"]
    );

    const derivedKey = await window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: opsLimit,
        hash: "SHA-256"
      },
      passwordKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );

    // Decrypt the private key
    const decryptedPrivateKey = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: nonce
      },
      derivedKey,
      encryptedPrivateKey
    );

    console.log('Private key decrypted successfully');
    return new Uint8Array(decryptedPrivateKey);
  } catch (error) {
    console.error('Decryption error:', error);
    throw new CryptoError("Failed to decrypt private key", error);
  }
}

export async function signChallenge(
  challenge: Uint8Array,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  try {
    // Sign the challenge using the polyfill
    const signature = signEd25519(privateKey, challenge);
    return signature;
  } catch (error) {
    console.error('Signature error:', error);
    throw new CryptoError("Failed to sign challenge", error);
  }
} 