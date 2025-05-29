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
    verified: boolean;  // TOFU verification status
    lastVerified: string; // ISO timestamp of last verification
}

export const storage = {
    // Save a new key bundle or update existing one
    saveKeyBundle: (keyBundle: KeyBundle) => {
        // Get existing bundles
        const existingBundlesStr = Cookies.get(STORAGE_KEYS.KEY_BUNDLES);
        let bundles: { [username: string]: KeyBundle } = {};
        
        if (existingBundlesStr) {
            try {
                bundles = JSON.parse(existingBundlesStr);
            } catch (e) {
                console.error('Error parsing existing key bundles:', e);
            }
        }

        // Add or update the bundle
        bundles[keyBundle.username] = {
            ...keyBundle,
            lastVerified: keyBundle.lastVerified || new Date().toISOString()
        };

        // Store in secure cookie
        Cookies.set(STORAGE_KEYS.KEY_BUNDLES, JSON.stringify(bundles), {
            secure: true,
            sameSite: 'strict',
            expires: 30 // Expires in 30 days
        });

        // Store current user separately for quick access
        if (keyBundle.username === Cookies.get(STORAGE_KEYS.CURRENT_USER)) {
            Cookies.set(STORAGE_KEYS.CURRENT_USER, keyBundle.username, {
                secure: true,
                sameSite: 'strict',
                expires: 30
            });
        }
    },

    // Get key bundle for a specific user
    getKeyBundle: (username: string): KeyBundle | null => {
        const bundlesStr = Cookies.get(STORAGE_KEYS.KEY_BUNDLES);
        if (!bundlesStr) return null;

        try {
            const bundles = JSON.parse(bundlesStr);
            return bundles[username] || null;
        } catch (e) {
            console.error('Error parsing key bundles:', e);
            return null;
        }
    },

    // Get all key bundles
    getAllKeyBundles: (): { [username: string]: KeyBundle } => {
        const bundlesStr = Cookies.get(STORAGE_KEYS.KEY_BUNDLES);
        if (!bundlesStr) return {};

        try {
            return JSON.parse(bundlesStr);
        } catch (e) {
            console.error('Error parsing key bundles:', e);
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
        Cookies.set(STORAGE_KEYS.CURRENT_USER, username, {
            secure: true,
            sameSite: 'strict',
            expires: 30
        });
    },

    // Get current user
    getCurrentUser: (): string | null => {
        return Cookies.get(STORAGE_KEYS.CURRENT_USER) || null;
    },

    // Clear all stored data
    clearStorage: () => {
        Cookies.remove(STORAGE_KEYS.KEY_BUNDLES);
        Cookies.remove(STORAGE_KEYS.CURRENT_USER);
        Cookies.remove(STORAGE_KEYS.AUTH_TOKEN);
    }
};
