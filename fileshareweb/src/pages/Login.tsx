import React, { useState } from 'react';
import { 
  Box, 
  Container, 
  Typography, 
  TextField, 
  Button, 
  Link,
  Paper,
  Grid,
  InputAdornment,
  IconButton,
  Alert,
} from '@mui/material';
import { useNavigate } from 'react-router-dom';
import { Visibility, VisibilityOff, Login as LoginIcon, Lock, Person, Home } from '@mui/icons-material';
import { MatrixBackground } from '../components';

const Login: React.FC = () => {
  const navigate = useNavigate();
  const [showPassword, setShowPassword] = useState(false);
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
  });
  const [error, setError] = useState('');

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    // TODO: Implement login logic
    navigate('/dashboard');
  };

  return (
    <>
      <MatrixBackground />
      <Box
        sx={{
          minHeight: '100vh',
          background: 'rgba(0,0,0,0.5)', // or 'transparent'
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
                Secure your files
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
                startIcon={<LoginIcon />}
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
                DECRYPT & LOGIN
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
                  Need an encrypted account? Sign Up
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