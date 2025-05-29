import Cookies from 'js-cookie';

const STORAGE_KEYS = {
    KEY_BUNDLES: 'key_bundles', // Store all key bundles
    CURRENT_USER: 'current_user',
    AUTH_TOKEN: 'auth_token'
};

interface KeyBundle {
    username: string;
    IK_pub: string;
    SPK_pub: string;
    SPK_signature: string;
    OPKs: string[];
    IK_priv?: string;
    SPK_priv?: string;
    OPKs_priv?: string[];
    secretKey?: string;  // Added for private key
    pdk?: string;        // Added for password-derived key
    kek?: string;        // Added for key encryption key
    verified: boolean;  // TOFU verification status
    lastVerified: string; // ISO timestamp of last verification
}

// Helper to get the session storage key for a specific user
const getUserKeyBundleKey = (username: string) => `key_bundle_${username}`;

export const storage = {
    // Save a key bundle for a specific user
    saveKeyBundle: (keyBundle: KeyBundle) => {
        const key = getUserKeyBundleKey(keyBundle.username);
        sessionStorage.setItem(key, JSON.stringify(keyBundle));
        
        // Also save to cookies for persistence
        const allBundles = storage.getAllKeyBundles();
        allBundles[keyBundle.username] = keyBundle;
        Cookies.set(STORAGE_KEYS.KEY_BUNDLES, JSON.stringify(allBundles));
    },

    // Get a key bundle for a specific user
    getKeyBundle: (username: string): KeyBundle | null => {
        const key = getUserKeyBundleKey(username);
        const bundleStr = sessionStorage.getItem(key);
        if (!bundleStr) return null;
        try {
            return JSON.parse(bundleStr);
        } catch (e) {
            console.error('Error parsing key bundle:', e);
            return null;
        }
    },

    // Get all key bundles from cookies
    getAllKeyBundles: (): Record<string, KeyBundle> => {
        const bundlesStr = Cookies.get(STORAGE_KEYS.KEY_BUNDLES);
        if (!bundlesStr) return {};
        try {
            return JSON.parse(bundlesStr);
        } catch (e) {
            console.error('Error parsing all key bundles:', e);
            return {};
        }
    },

    // Update verification status for a user
    updateVerificationStatus: (username: string, verified: boolean) => {
        const bundlesStr = Cookies.get(STORAGE_KEYS.KEY_BUNDLES);
        if (!bundlesStr) return;

        try {
            const bundles = JSON.parse(bundlesStr);
            if (bundles[username]) {
                bundles[username] = {
                    ...bundles[username],
                    verified,
                    lastVerified: new Date().toISOString()
                };
                Cookies.set(STORAGE_KEYS.KEY_BUNDLES, JSON.stringify(bundles), {
                    secure: true,
                    sameSite: 'strict',
                    expires: 30
                });
            }
        } catch (e) {
            console.error('Error updating verification status:', e);
        }
    },

    // Set current user
    setCurrentUser: (username: string) => {
        sessionStorage.setItem(STORAGE_KEYS.CURRENT_USER, username);
    },

    // Get current user
    getCurrentUser: (): string | null => {
        return sessionStorage.getItem(STORAGE_KEYS.CURRENT_USER);
    },

    // Clear all session data
    clearSession: () => {
        // Clear all key bundles from sessionStorage
        Object.keys(sessionStorage).forEach(key => {
            if (key.startsWith('key_bundle_')) {
                sessionStorage.removeItem(key);
            }
        });
        sessionStorage.removeItem(STORAGE_KEYS.CURRENT_USER);
    }
};
