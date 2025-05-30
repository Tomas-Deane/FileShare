import sodium from 'libsodium-wrappers-sumo';
import { KeyBundle } from './storage';

class SecureStorage {
    private static instance: SecureStorage;
    private memoryStore: Map<string, { data: Uint8Array, expiry: number }> = new Map();
    private readonly MEMORY_CLEAR_TIMEOUT = 30000; // 30 seconds
    private readonly MAX_SESSION_DURATION = 3600000; // 1 hour
    private sessionStartTime: number;

    private constructor() {
        this.sessionStartTime = Date.now();
        setInterval(() => this.cleanup(), 1000);
    }

    static getInstance(): SecureStorage {
        if (!SecureStorage.instance) {
            SecureStorage.instance = new SecureStorage();
        }
        return SecureStorage.instance;
    }

    // Check if session has expired
    private isSessionExpired(): boolean {
        return Date.now() - this.sessionStartTime > this.MAX_SESSION_DURATION;
    }

    // Generate a session-specific key
    private async generateSessionKey(): Promise<Uint8Array> {
        const sessionKey = new Uint8Array(32);
        window.crypto.getRandomValues(sessionKey);
        return sessionKey;
    }

    // Store sensitive data with additional security measures
    async storeSensitiveData(key: string, data: Uint8Array, pdk: Uint8Array): Promise<void> {
        if (this.isSessionExpired()) {
            this.clearAllData();
            throw new Error('Session expired');
        }

        // Generate a session-specific encryption key
        const sessionKey = await this.generateSessionKey();
        
        // Encrypt the data with both PDK and session key
        const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        const encryptedData = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
            data,
            null,
            null,
            nonce,
            sessionKey
        );

        // Store encrypted data in memory with expiry
        this.memoryStore.set(key, {
            data: encryptedData,
            expiry: Date.now() + this.MEMORY_CLEAR_TIMEOUT
        });

        // Store session key encrypted with PDK in sessionStorage
        const encryptedSessionKey = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
            sessionKey,
            null,
            null,
            nonce,
            pdk
        );

        sessionStorage.setItem(`${key}_session`, JSON.stringify({
            data: btoa(String.fromCharCode.apply(null, Array.from(encryptedSessionKey))),
            nonce: btoa(String.fromCharCode.apply(null, Array.from(nonce))),
            expiry: Date.now() + this.MEMORY_CLEAR_TIMEOUT
        }));
    }

    // Retrieve sensitive data with security checks
    async getSensitiveData(key: string, pdk: Uint8Array): Promise<Uint8Array | null> {
        if (this.isSessionExpired()) {
            this.clearAllData();
            return null;
        }

        const sessionData = sessionStorage.getItem(`${key}_session`);
        if (!sessionData) return null;

        try {
            const { data, nonce, expiry } = JSON.parse(sessionData);
            
            // Check if session key has expired
            if (Date.now() > expiry) {
                this.clearSensitiveData(key);
                return null;
            }

            // Decrypt session key with PDK
            const encryptedSessionKey = Uint8Array.from(atob(data), c => c.charCodeAt(0));
            const nonceBytes = Uint8Array.from(atob(nonce), c => c.charCodeAt(0));
            const sessionKey = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                null,
                encryptedSessionKey,
                null,
                nonceBytes,
                pdk
            );

            // Get encrypted data from memory
            const memoryData = this.memoryStore.get(key);
            if (!memoryData) return null;

            // Decrypt data with session key
            const decryptedData = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                null,
                memoryData.data,
                null,
                nonceBytes,
                sessionKey
            );

            return decryptedData;
        } catch (error) {
            console.error('Error retrieving sensitive data:', error);
            this.clearSensitiveData(key);
            return null;
        }
    }

    // Clear sensitive data
    clearSensitiveData(key: string): void {
        const memoryData = this.memoryStore.get(key);
        if (memoryData) {
            // Securely wipe the memory
            for (let i = 0; i < memoryData.data.length; i++) {
                memoryData.data[i] = 0;
            }
            this.memoryStore.delete(key);
        }
        sessionStorage.removeItem(`${key}_session`);
    }

    // Clear all data
    clearAllData(): void {
        Array.from(this.memoryStore.keys()).forEach(key => {
            this.clearSensitiveData(key);
        });
        this.memoryStore.clear();
        this.sessionStartTime = Date.now();
    }

    setCurrentUser(username: string): void {
        sessionStorage.setItem('current_user', username);
    }

    getCurrentUser(): string | null {
        return sessionStorage.getItem('current_user');
    }

    private cleanup(): void {
        const now = Date.now();
        Array.from(this.memoryStore.entries()).forEach(([key, value]) => {
            if (now >= value.expiry) {
                this.clearSensitiveData(key);
            }
        });
    }
}

// Export a singleton instance
export const secureStorage = SecureStorage.getInstance();
