import React, { useState, useEffect } from 'react';
import { 
  Box, 
  Container, 
  Typography, 
  TextField, 
  Button, 
  Link,
  Paper,
  InputAdornment,
  IconButton,
  Alert,
  CircularProgress,
} from '@mui/material';
import { useNavigate } from 'react-router-dom';
import { Visibility, VisibilityOff, Security, Lock, Person, Home } from '@mui/icons-material';
import { MatrixBackground } from '../components';
import { apiClient } from '../utils/apiClient';
import { generateKeyPair, encryptPrivateKey, generateSalt, derivePDK, generateKEK, encryptKEK, CryptoError, generateX3DHKeys } from '../utils/crypto';
import sodium from 'libsodium-wrappers-sumo';
import { storage } from '../utils/storage';
import base64 from 'base64-js';

interface SignupResponse {
  status: string;
  detail?: string;
}

interface ChallengeResponse {
  nonce: string;
}

const Signup: React.FC = () => {
  const navigate = useNavigate();
  const [showPassword, setShowPassword] = useState(false);
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
  });
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isBrowserCompatible, setIsBrowserCompatible] = useState(true);

  useEffect(() => {
    // Check browser compatibility
    try {
      if (!window.crypto || !window.crypto.subtle) {
        setIsBrowserCompatible(false);
        setError('Your browser does not support the required security features. Please use a modern browser like Chrome, Firefox, or Edge.');
        return;
      }

      // Test basic crypto support
      window.crypto.getRandomValues(new Uint8Array(32));
    } catch (err) {
      setIsBrowserCompatible(false);
      setError('Your browser does not support the required security features. Please use a modern browser like Chrome, Firefox, or Edge.');
    }
  }, []);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      // Validate input
      if (!formData.username || !formData.password) {
        throw new Error('Username and password are required');
      }

      const trimmedUsername = formData.username.trim();
      if (!trimmedUsername) {
        throw new Error('Username cannot be empty or contain only spaces');
      }

      if (formData.password.length < 8) {
        throw new Error('Password must be at least 8 characters long');
      }

      if (!isBrowserCompatible) {
        throw new Error('Your browser is not compatible with the required security features');
      }

      console.log('Starting signup process...');
      
      // Generate cryptographic keys and salt
      console.log('Generating key pair...');
      const { publicKey, privateKey } = await generateKeyPair();
      
      console.log('Generating X3DH keys...');
      const x3dhKeys = await generateX3DHKeys();
      
      console.log('Generating salt...');
      const salt = await generateSalt();
      
      console.log('Deriving PDK...');
      const pdk = await derivePDK(formData.password, salt, 3, 67108864);
      
      console.log('Generating KEK...');
      const kek = await generateKEK();
      const kekNonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
      const privateKeyNonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
      
      console.log('Encrypting private key...');
      const { encryptedPrivateKey, nonce: encryptedNonce } = await encryptPrivateKey(
        privateKey,
        pdk,
        privateKeyNonce
      );

      console.log('Encrypting KEK...');
      const { encryptedPrivateKey: encryptedKek, nonce: encryptedKekNonce } = await encryptKEK(
        kek,
        pdk,
        kekNonce
      );

      // Convert binary data to base64 strings
      console.log('Preparing payload...');
      const payload = {
        username: trimmedUsername,
        salt: btoa(String.fromCharCode.apply(null, Array.from(salt))),
        argon2_opslimit: 3,
        argon2_memlimit: 67108864,
        public_key: btoa(String.fromCharCode.apply(null, Array.from(publicKey))),
        encrypted_privkey: btoa(String.fromCharCode.apply(null, Array.from(encryptedPrivateKey))),
        privkey_nonce: btoa(String.fromCharCode.apply(null, Array.from(encryptedNonce))),
        encrypted_kek: btoa(String.fromCharCode.apply(null, Array.from(encryptedKek))),
        kek_nonce: btoa(String.fromCharCode.apply(null, Array.from(encryptedKekNonce))),
        identity_key: btoa(String.fromCharCode.apply(null, Array.from(x3dhKeys.identity_key))),
        signed_pre_key: btoa(String.fromCharCode.apply(null, Array.from(x3dhKeys.signed_pre_key))),
        signed_pre_key_sig: btoa(String.fromCharCode.apply(null, Array.from(x3dhKeys.signed_pre_key_sig))),
        one_time_pre_keys: x3dhKeys.one_time_pre_keys.map(key => 
          btoa(String.fromCharCode.apply(null, Array.from(key)))
        )
      };

      // Make API call
      console.log('Sending signup request...');
      const response = await apiClient.post<SignupResponse>('/signup', payload);
      
      if (response.status === 'ok') {
        // 1. Save to local storage
        storage.saveKeyBundle({
            username: trimmedUsername,
            IK_pub: btoa(String.fromCharCode.apply(null, Array.from(x3dhKeys.identity_key))),
            SPK_pub: btoa(String.fromCharCode.apply(null, Array.from(x3dhKeys.signed_pre_key))),
            SPK_signature: btoa(String.fromCharCode.apply(null, Array.from(x3dhKeys.signed_pre_key_sig))),
            OPKs: x3dhKeys.one_time_pre_keys.map(key => 
                btoa(String.fromCharCode.apply(null, Array.from(key)))
            ),
            verified: false,
            lastVerified: new Date().toISOString()
        });

        // 2. Create encrypted backup for server
        const backupData = {
            privateKey: btoa(String.fromCharCode.apply(null, Array.from(privateKey))),
            identityKey: btoa(String.fromCharCode.apply(null, Array.from(x3dhKeys.identity_key))),
            signedPreKey: btoa(String.fromCharCode.apply(null, Array.from(x3dhKeys.signed_pre_key))),
            signedPreKeySig: btoa(String.fromCharCode.apply(null, Array.from(x3dhKeys.signed_pre_key_sig))),
            oneTimePreKeys: x3dhKeys.one_time_pre_keys.map(key => 
                btoa(String.fromCharCode.apply(null, Array.from(key)))
            )
        };

        // Encrypt backup with password-derived key
        const backupNonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        const backupKey = await derivePDK(formData.password, salt, 3, 67108864);
        const encryptedBackup = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
            JSON.stringify(backupData),
            null,
            null,
            backupNonce,
            backupKey
        );

        // 3. Get challenge for backup
        const challengeResponse = await apiClient.post<ChallengeResponse>('/challenge', {
            username: trimmedUsername,
            operation: 'backup_tofu'
        });

        // 4. Sign and send backup
        const signature = sodium.crypto_sign_detached(
            base64.toByteArray(challengeResponse.nonce),
            privateKey
        );

        await apiClient.post('/backup_tofu_keys', {
            username: trimmedUsername,
            encrypted_backup: btoa(String.fromCharCode.apply(null, Array.from(encryptedBackup))),
            backup_nonce: btoa(String.fromCharCode.apply(null, Array.from(backupNonce))),
            nonce: challengeResponse.nonce,
            signature: btoa(String.fromCharCode.apply(null, Array.from(signature)))
        });

        // Set as current user
        storage.setCurrentUser(trimmedUsername);

        console.log('Signup successful, redirecting to login...');
        navigate('/login');
      } else {
        setError(response.detail || 'Signup failed');
      }
    } catch (err: any) {
      console.error('Signup error:', err);
      if (err instanceof CryptoError) {
        console.error('Crypto error details:', err.cause);
        setError('Failed to generate secure keys. Please try again or use a different browser.');
      } else if (err.message?.includes('SSL Certificate Error')) {
        // Show a more user-friendly message for SSL certificate errors
        setError(
          'The server is using a self-signed certificate. This is expected in development. ' +
          'Please proceed with caution. If you\'re in a production environment, ' +
          'please contact the administrator.'
        );
      } else if (err.message?.includes('Unable to establish a secure connection')) {
        setError('Unable to establish a secure connection to the server. Please ensure you\'re using a trusted network and try again.');
      } else if (err.response?.data?.detail) {
        setError(err.response.data.detail);
      } else if (err.message) {
        setError(err.message);
      } else {
        setError('An unexpected error occurred during signup');
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <>
      <MatrixBackground />
      <Box
        sx={{
          minHeight: '100vh',
          background: 'rgba(0,0,0,0.5)',
          display: 'flex',
          alignItems: 'center',
          py: 4,
          position: 'relative',
          zIndex: 1,
        }}
      >
        <Container maxWidth="sm">
          <Paper
            elevation={24}
            sx={{
              p: 4,
              background: 'rgba(0, 0, 0, 0.8)',
              backdropFilter: 'blur(10px)',
              border: '1px solid rgba(0, 255, 0, 0.2)',
              borderRadius: 2,
              boxShadow: '0 0 20px rgba(0, 255, 0, 0.2)',
              position: 'relative',
            }}
          >
            <Box sx={{ position: 'absolute', top: 16, left: 16 }}>
              <Button
                variant="outlined"
                onClick={() => navigate('/')}
                startIcon={<Home />}
                sx={{
                  color: '#00ff00',
                  borderColor: 'rgba(0, 255, 0, 0.3)',
                  '&:hover': {
                    borderColor: '#00ff00',
                    backgroundColor: 'rgba(0, 255, 0, 0.1)',
                  },
                }}
              >
                Home
              </Button>
            </Box>
            <Box sx={{ textAlign: 'center', mb: 4 }}>
              <Typography
                component="h1"
                variant="h4"
                sx={{
                  color: '#00ff00',
                  textShadow: '0 0 10px rgba(0, 255, 0, 0.5)',
                  fontFamily: 'monospace',
                  fontWeight: 'bold',
                  letterSpacing: 2,
                }}
              >
                SIGNUP
              </Typography>
              <Typography
                variant="subtitle1"
                sx={{
                  color: '#00ffff',
                  mt: 1,
                  fontFamily: 'monospace',
                }}
              >
                Create your encrypted account
              </Typography>
            </Box>

            {error && (
              <Alert severity="error" sx={{ mb: 2, bgcolor: 'rgba(255, 0, 0, 0.1)' }}>
                {error}
              </Alert>
            )}
            <Box component="form" onSubmit={handleSubmit}>
              <TextField
                required
                fullWidth
                id="username"
                label="Username"
                name="username"
                autoComplete="username"
                value={formData.username}
                onChange={handleChange}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <Person sx={{ color: '#00ff00' }} />
                    </InputAdornment>
                  ),
                }}
                sx={{
                  mt: 2,
                  mb: 2,
                  width: '98%',
                  alignSelf: 'center',
                  '& .MuiOutlinedInput-root': {
                    '& fieldset': {
                      borderColor: 'rgba(0, 255, 0, 0.3)',
                    },
                    '&:hover fieldset': {
                      borderColor: 'rgba(0, 255, 0, 0.5)',
                    },
                    '&.Mui-focused fieldset': {
                      borderColor: '#00ff00',
                    },
                    height: '56px',
                  },
                  '& .MuiInputLabel-root': {
                    color: 'rgba(0, 255, 0, 0.7)',
                  },
                  '& .MuiInputBase-input': {
                    color: '#fff',
                    padding: '16.5px 14px',
                  },
                  '& .MuiInputAdornment-root': {
                    marginRight: '8px',
                  },
                  '& input:-webkit-autofill': {
                    WebkitBoxShadow: '0 0 0 1000px #111 inset, 0 0 8px 2px #00ff00',
                    WebkitTextFillColor: '#00ff00',
                    borderColor: '#00ff00',
                    transition: 'background-color 5000s ease-in-out 0s',
                  },
                  '& input:-webkit-autofill:focus': {
                    WebkitBoxShadow: '0 0 0 1000px #111 inset, 0 0 8px 2px #00ff00',
                    WebkitTextFillColor: '#00ff00',
                    borderColor: '#00ff00',
                  },
                }}
              />
              <TextField
                required
                fullWidth
                name="password"
                label="Password"
                type={showPassword ? 'text' : 'password'}
                id="password"
                autoComplete="new-password"
                value={formData.password}
                onChange={handleChange}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <Lock sx={{ color: '#00ff00' }} />
                    </InputAdornment>
                  ),
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton
                        onClick={() => setShowPassword(!showPassword)}
                        edge="end"
                        sx={{ color: '#00ff00' }}
                      >
                        {showPassword ? <VisibilityOff /> : <Visibility />}
                      </IconButton>
                    </InputAdornment>
                  ),
                }}
                sx={{
                  mt: 2,
                  mb: 2,
                  width: '98%',
                  alignSelf: 'center',
                  '& .MuiOutlinedInput-root': {
                    '& fieldset': {
                      borderColor: 'rgba(0, 255, 0, 0.3)',
                    },
                    '&:hover fieldset': {
                      borderColor: 'rgba(0, 255, 0, 0.5)',
                    },
                    '&.Mui-focused fieldset': {
                      borderColor: '#00ff00',
                    },
                    height: '56px',
                  },
                  '& .MuiInputLabel-root': {
                    color: 'rgba(0, 255, 0, 0.7)',
                  },
                  '& .MuiInputBase-input': {
                    color: '#fff',
                    padding: '16.5px 14px',
                  },
                  '& .MuiInputAdornment-root': {
                    marginRight: '8px',
                  },
                  '& input:-webkit-autofill': {
                    WebkitBoxShadow: '0 0 0 1000px #111 inset, 0 0 8px 2px #00ff00',
                    WebkitTextFillColor: '#00ff00',
                    borderColor: '#00ff00',
                    transition: 'background-color 5000s ease-in-out 0s',
                  },
                  '& input:-webkit-autofill:focus': {
                    WebkitBoxShadow: '0 0 0 1000px #111 inset, 0 0 8px 2px #00ff00',
                    WebkitTextFillColor: '#00ff00',
                    borderColor: '#00ff00',
                  },
                }}
              />

              <Button
                type="submit"
                fullWidth
                variant="contained"
                startIcon={isLoading ? <CircularProgress size={20} color="inherit" /> : <Security />}
                disabled={isLoading}
                sx={{
                  mt: 3,
                  mb: 2,
                  py: 1.5,
                  background: 'linear-gradient(45deg, #00ff00 30%, #00ffff 90%)',
                  color: '#000',
                  fontWeight: 'bold',
                  '&:hover': {
                    background: 'linear-gradient(45deg, #00ffff 30%, #00ff00 90%)',
                    boxShadow: '0 0 20px rgba(0, 255, 0, 0.5)',
                  },
                }}
              >
                {isLoading ? 'ENCRYPTING...' : 'ENCRYPT & SIGNUP'}
              </Button>

              <Box sx={{ textAlign: 'center' }}>
                <Link
                  href="/login"
                  variant="body2"
                  sx={{
                    color: '#00ffff',
                    textDecoration: 'none',
                    '&:hover': {
                      textDecoration: 'underline',
                      color: '#00ff00',
                    },
                  }}
                >
                  Already have an encrypted account? Sign In
                </Link>
              </Box>
            </Box>
          </Paper>
        </Container>
      </Box>
    </>
  );
};

export default Signup;