const STORAGE_KEYS = {
    KEY_BUNDLES: 'key_bundles', // Store all key bundles
    CURRENT_USER: 'current_user',
    AUTH_TOKEN: 'auth_token'
};

export interface PreKeyBundle {
    IK_pub: string;
    SPK_pub: string;
    SPK_signature: string;
}

export interface RecipientKeyBundle {
    data: PreKeyBundle;  // Changed from string to PreKeyBundle
    verified: boolean;
}

export interface KeyBundle {
    username: string;
    IK_pub: string;
    SPK_pub: string;
    SPK_signature: string;
    OPKs: string[];
    IK_priv: string;
    SPK_priv: string;
    OPKs_priv: string[];
    secretKey: string;
    pdk: string;
    kek: string;
    verified: boolean;  // TOFU verification status
    lastVerified: string; // ISO timestamp of last verification
    recipients?: { [username: string]: RecipientKeyBundle };
}

export const storage = {
    // Save a new key bundle or update existing one
    saveKeyBundle: (keyBundle: KeyBundle) => {
        // Get existing bundles
        const existingBundlesStr = sessionStorage.getItem(STORAGE_KEYS.KEY_BUNDLES);
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

        // Store in sessionStorage
        sessionStorage.setItem(STORAGE_KEYS.KEY_BUNDLES, JSON.stringify(bundles));

        // Store current user separately for quick access
        if (keyBundle.username === sessionStorage.getItem(STORAGE_KEYS.CURRENT_USER)) {
            sessionStorage.setItem(STORAGE_KEYS.CURRENT_USER, keyBundle.username);
        }
    },

    // Get key bundle for a specific user
    getKeyBundle: (username: string): KeyBundle | null => {
        const bundlesStr = sessionStorage.getItem(STORAGE_KEYS.KEY_BUNDLES);
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
        const bundlesStr = sessionStorage.getItem(STORAGE_KEYS.KEY_BUNDLES);
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
        const bundlesStr = sessionStorage.getItem(STORAGE_KEYS.KEY_BUNDLES);
        if (!bundlesStr) return;

        try {
            const bundles = JSON.parse(bundlesStr);
            if (bundles[username]) {
                bundles[username] = {
                    ...bundles[username],
                    verified,
                    lastVerified: new Date().toISOString()
                };
                sessionStorage.setItem(STORAGE_KEYS.KEY_BUNDLES, JSON.stringify(bundles));
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

    // Clear all stored data
    clearStorage: () => {
        sessionStorage.removeItem(STORAGE_KEYS.KEY_BUNDLES);
        sessionStorage.removeItem(STORAGE_KEYS.CURRENT_USER);
        sessionStorage.removeItem(STORAGE_KEYS.AUTH_TOKEN);
    },

    // Remove a specific user's key bundle
    removeKeyBundle: (username: string) => {
        const bundlesStr = sessionStorage.getItem(STORAGE_KEYS.KEY_BUNDLES);
        if (!bundlesStr) return;
        try {
            const bundles = JSON.parse(bundlesStr);
            delete bundles[username];
            sessionStorage.setItem(STORAGE_KEYS.KEY_BUNDLES, JSON.stringify(bundles));
        } catch (e) {
            console.error('Error removing key bundle:', e);
        }
    }
};