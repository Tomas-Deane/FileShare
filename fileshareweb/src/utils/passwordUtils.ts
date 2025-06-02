import { SHA1 } from 'crypto-js';
import { apiClient } from './apiClient';

export const checkPwnedPassword = async (password: string): Promise<number> => {
  try {
    // Hash the password using SHA-1
    const hash = SHA1(password).toString().toUpperCase();
    const prefix = hash.substring(0, 5);
    const suffix = hash.substring(5);

    // Call the Pwned Passwords API
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    if (!response.ok) {
      throw new Error('Failed to check password');
    }

    const text = await response.text();
    const hashes = text.split('\r\n');
    
    // Find the matching hash suffix
    const match = hashes.find(h => h.startsWith(suffix));
    if (match) {
      // Extract the count from the response
      const count = parseInt(match.split(':')[1]);
      return count;
    }

    return 0;
  } catch (error) {
    console.error('Error checking pwned password:', error);
    return 0;
  }
};

export const validatePassword = async (password: string): Promise<{ isValid: boolean; message: string }> => {
  // Check minimum length (8 characters as per OWASP)
  if (password.length < 8) {
    return {
      isValid: false,
      message: 'Password must be at least 8 characters long'
    };
  }

  // Check maximum length (128 characters to allow for passphrases)
  if (password.length > 128) {
    return {
      isValid: false,
      message: 'Password must not exceed 128 characters'
    };
  }

  // Check if password has been pwned
  const pwnedCount = await checkPwnedPassword(password);
  if (pwnedCount > 0) {
    return {
      isValid: false,
      message: `This password has been found in ${pwnedCount} data breaches. Please choose a different password.`
    };
  }

  return {
    isValid: true,
    message: 'Password is valid'
  };
};

export interface PasswordLeakInfo {
  leakDate: string;
  leakSource: string;
  affectedUsers: string[];
}

export const handlePasswordLeak = async (
  leakInfo: PasswordLeakInfo,
  forceRotation: boolean = true
): Promise<void> => {
  try {
    // Store leak information
    await apiClient.post('/password-leak', {
      leak_date: leakInfo.leakDate,
      leak_source: leakInfo.leakSource,
      affected_users: leakInfo.affectedUsers,
      force_rotation: forceRotation
    });

    // If force rotation is enabled, mark affected users for password change
    if (forceRotation) {
      await apiClient.post('/force-password-change', {
        affected_users: leakInfo.affectedUsers
      });
    }
  } catch (error) {
    console.error('Error handling password leak:', error);
    throw error;
  }
}; 