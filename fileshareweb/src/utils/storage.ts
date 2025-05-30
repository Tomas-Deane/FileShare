import { secureStorage } from './secureStorage';
import { derivePDK, KeyBundle } from './crypto';

const STORAGE_KEYS = {
    KEY_BUNDLES: 'key_bundles', // Store all key bundles
    CURRENT_USER: 'current_user',
    AUTH_TOKEN: 'auth_token'
};

// Helper to get the session storage key for a specific user
const getUserKeyBundleKey = (username: string) => `key_bundle_${username}`;

class Storage {
    private masterKey: Uint8Array | null = null;

    async initializeMasterKey(password: string, salt: Uint8Array) {
        this.masterKey = await derivePDK(password, salt, 3, 67108864);
    }

    async saveKeyBundle(keyBundle: KeyBundle): Promise<void> {
        if (!this.masterKey) {
            throw new Error('Master key not initialized');
        }
        await secureStorage.saveKeyBundle(keyBundle, this.masterKey);
    }

    async getKeyBundle(username: string): Promise<KeyBundle | null> {
        if (!this.masterKey) {
            throw new Error('Master key not initialized');
        }
        return await secureStorage.getKeyBundle(username, this.masterKey);
    }

    async deleteKeyBundle(username: string): Promise<void> {
        await secureStorage.deleteKeyBundle(username);
    }

    async clearAll(): Promise<void> {
        await secureStorage.clearAll();
    }

    setCurrentUser(username: string): void {
        localStorage.setItem('currentUser', username);
    }

    getCurrentUser(): string | null {
        return localStorage.getItem('currentUser');
    }
}

export const storage = new Storage();
