import { openDB, DBSchema, IDBPDatabase } from 'idb';
import { sodium } from './sodium';
import { KeyBundle, EncryptedKeyBundle } from './crypto';

interface SecureStorageSchema extends DBSchema {
  keyBundles: {
    key: string; // username
    value: EncryptedKeyBundle;
    indexes: { 'by-username': string };
  };
}

class SecureStorage {
  private db: IDBPDatabase<SecureStorageSchema> | null = null;
  private readonly DB_NAME = 'FileShareSecureDB';
  private readonly DB_VERSION = 1;

  async initialize() {
    if (!this.db) {
      this.db = await openDB<SecureStorageSchema>(this.DB_NAME, this.DB_VERSION, {
        upgrade(db) {
          const store = db.createObjectStore('keyBundles', { keyPath: 'username' });
          store.createIndex('by-username', 'username', { unique: true });
        },
      });
    }
    return this.db;
  }

  async saveKeyBundle(keyBundle: KeyBundle, masterKey: Uint8Array) {
    const db = await this.initialize();
    
    const iv = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    
    const encryptedData = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      JSON.stringify(keyBundle),
      null,
      null,
      iv,
      masterKey
    );

    const encryptedBundle: EncryptedKeyBundle = {
      ...keyBundle,
      encrypted: true,
      iv: iv,
      _encryptedData: btoa(String.fromCharCode.apply(null, Array.from(encryptedData)))
    };

    await db.put('keyBundles', encryptedBundle);
  }

  async getKeyBundle(username: string, masterKey: Uint8Array): Promise<KeyBundle | null> {
    const db = await this.initialize();
    const encryptedBundle = await db.get('keyBundles', username);
    
    if (!encryptedBundle) {
      return null;
    }

    if (!encryptedBundle.encrypted) {
      return encryptedBundle;
    }

    const encryptedData = Uint8Array.from(atob(encryptedBundle._encryptedData!), c => c.charCodeAt(0));
    const decryptedData = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      encryptedData,
      null,
      encryptedBundle.iv!,
      masterKey
    );

    return JSON.parse(new TextDecoder().decode(decryptedData));
  }

  async deleteKeyBundle(username: string) {
    const db = await this.initialize();
    await db.delete('keyBundles', username);
  }

  async clearAll() {
    const db = await this.initialize();
    await db.clear('keyBundles');
  }
}

export const secureStorage = new SecureStorage();
