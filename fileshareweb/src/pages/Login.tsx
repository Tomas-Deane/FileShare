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
import { signChallenge, decryptPrivateKey, derivePDK, decryptKEK, CryptoError } from '../utils/crypto';
import { useAuth } from '../contexts/AuthContext';

interface LoginChallenge {
  status: string;
  nonce: string;
  salt: string;
  argon2_opslimit: number;
  argon2_memlimit: number;
  encrypted_privkey: string;
  privkey_nonce: string;
  encrypted_kek: string;
  kek_nonce: string;
  detail?: string;
}

interface LoginResponse {
  status: string;
  message?: string;
  detail?: string;
}

const Login: React.FC = () => {
  const navigate = useNavigate();
  const { setAuthData } = useAuth();
  const [showPassword, setShowPassword] = useState(false);
  const [formData, setFormData] = useState({
    username: '',
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

      if (!isBrowserCompatible) {
        throw new Error('Your browser is not compatible with the required security features');
      }

      console.log('Starting login process...');
      
      // Step 1: Request login challenge
      console.log('Requesting login challenge...');
      const challengeResponse = await apiClient.post<LoginChallenge>('/login', {
        username: trimmedUsername
      });

      if (challengeResponse.status !== 'challenge') {
        throw new Error(challengeResponse.detail || 'Login failed');
      }

      // Step 2: Derive PDK and decrypt private key
      console.log('Deriving PDK...');
      const salt = Uint8Array.from(atob(challengeResponse.salt), c => c.charCodeAt(0));
      const pdk = await derivePDK(
        formData.password,
        salt,
        challengeResponse.argon2_opslimit,
        challengeResponse.argon2_memlimit
      );

      console.log('Decrypting private key...');
      const encryptedPrivateKey = Uint8Array.from(atob(challengeResponse.encrypted_privkey), c => c.charCodeAt(0));
      const nonce = Uint8Array.from(atob(challengeResponse.privkey_nonce), c => c.charCodeAt(0));
      const privateKey = await decryptPrivateKey(encryptedPrivateKey, pdk, nonce);

      console.log('Signing challenge...');
      const challenge = Uint8Array.from(atob(challengeResponse.nonce), c => c.charCodeAt(0));
      const signature = await signChallenge(challenge, privateKey);

      // Step 3: Authenticate with signed challenge
      console.log('Authenticating...');
      const authResponse = await apiClient.post<LoginResponse>('/authenticate', {
        username: trimmedUsername,
        nonce: challengeResponse.nonce,
        signature: btoa(String.fromCharCode.apply(null, Array.from(signature)))
      });

      if (authResponse.status === 'ok') {
        console.log('Login successful, saving auth data...');
        
        // Decrypt KEK
        const encryptedKek = Uint8Array.from(atob(challengeResponse.encrypted_kek), c => c.charCodeAt(0));
        const kekNonce = Uint8Array.from(atob(challengeResponse.kek_nonce), c => c.charCodeAt(0));
        const kek = await decryptKEK(encryptedKek, pdk, kekNonce);
        
        // Save the auth data
        setAuthData({
          username: trimmedUsername,
          secretKey: privateKey,
          pdk: pdk,
          kek: kek
        });

        // Navigate to dashboard
        navigate('/dashboard', { replace: true });
      } else {
        setError(authResponse.detail || 'Authentication failed');
      }
    } catch (err: any) {
      console.error('Login error:', err);
      if (err instanceof CryptoError) {
        console.error('Crypto error details:', err.cause);
        setError('Failed to decrypt private key. Please check your password and try again.');
      } else if (err.response?.data?.detail) {
        setError(err.response.data.detail);
      } else if (err.message) {
        setError(err.message);
      } else {
        setError('An unexpected error occurred during login');
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
                LOGIN
              </Typography>
              <Typography
                variant="subtitle1"
                sx={{
                  color: '#00ffff',
                  mt: 1,
                  fontFamily: 'monospace',
                }}
              >
                Access your encrypted account
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
                autoComplete="current-password"
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
                {isLoading ? 'DECRYPTING...' : 'DECRYPT & LOGIN'}
              </Button>

              <Box sx={{ textAlign: 'center' }}>
                <Link
                  href="/signup"
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
                  Don't have an encrypted account? Sign Up
                </Link>
              </Box>
            </Box>
          </Paper>
        </Container>
      </Box>
    </>
  );
};

export default Login;