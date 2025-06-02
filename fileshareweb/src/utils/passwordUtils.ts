import { SHA1 } from 'crypto-js';

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
  // Check minimum length (8 characters)
  if (password.length < 8) {
    return {
      isValid: false,
      message: 'Password must be at least 8 characters long'
    };
  }

  // Check maximum length (64 characters)
  if (password.length > 64) {
    return {
      isValid: false,
      message: 'Password must not exceed 64 characters'
    };
  }

  // Check for at least one uppercase letter
  if (!/[A-Z]/.test(password)) {
    return {
      isValid: false,
      message: 'Password must contain at least one uppercase letter'
    };
  }

  // Check for at least one lowercase letter
  if (!/[a-z]/.test(password)) {
    return {
      isValid: false,
      message: 'Password must contain at least one lowercase letter'
    };
  }

  // Check for at least one number
  if (!/\d/.test(password)) {
    return {
      isValid: false,
      message: 'Password must contain at least one number'
    };
  }

  // Check for at least one special character
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    return {
      isValid: false,
      message: 'Password must contain at least one special character (!@#$%^&*(),.?":{}|<>)'
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