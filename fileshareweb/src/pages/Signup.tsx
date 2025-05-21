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
  AppBar,
} from '@mui/material';
import { useNavigate } from 'react-router-dom';
import { Visibility, VisibilityOff, Security, Person, Lock, Home } from '@mui/icons-material';
import MatrixBackground from '../components/MatrixBackground.tsx';
import styled from '@emotion/styled';
import { Theme } from '@mui/material/styles';

const StyledAppBar = styled(AppBar)<{ theme?: Theme }>(({ theme }) => ({
  background: 'rgba(0, 0, 0, 0.8)',
  backdropFilter: 'blur(10px)',
  borderBottom: '1px solid rgba(0, 255, 0, 0.2)',
  '&::before': {
    content: '""',
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    background: 'linear-gradient(90deg, transparent 0%, rgba(0, 255, 0, 0.1) 50%, transparent 100%)',
    animation: 'pulse 2s ease-in-out infinite',
  },
}));

const NavButton = styled(Button)<{ theme?: Theme }>(({ theme }) => ({
  color: '#00ff00',
  borderColor: '#00ff00',
  position: 'relative',
  overflow: 'hidden',
  '&::before': {
    content: '""',
    position: 'absolute',
    top: 0,
    left: -100,
    width: '100%',
    height: '100%',
    background: 'linear-gradient(90deg, transparent, rgba(0, 255, 0, 0.2), transparent)',
    transition: '0.5s',
  },
  '&:hover': {
    borderColor: '#00ffff',
    color: '#00ffff',
    background: 'rgba(0, 255, 0, 0.1)',
    '&::before': {
      left: 100,
    },
  },
}));

const CyberButton = styled(Button)<{ theme?: Theme }>(({ theme }) => ({
  background: 'linear-gradient(45deg, #00ff00 30%, #00ffff 90%)',
  border: 0,
  borderRadius: 3,
  boxShadow: '0 3px 5px 2px rgba(0, 255, 0, .3)',
  color: '#000',
  height: 56,
  padding: '0 40px',
  fontSize: '1.4rem',
  textTransform: 'uppercase',
  letterSpacing: '0.1em',
  transition: 'all 0.3s ease',
  position: 'relative',
  overflow: 'hidden',
  '&::before': {
    content: '""',
    position: 'absolute',
    top: 0,
    left: -100,
    width: '100%',
    height: '100%',
    background: 'linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent)',
    transition: '0.5s',
  },
  '&:hover': {
    background: 'linear-gradient(45deg, #00ffff 30%, #00ff00 90%)',
    transform: 'scale(1.05)',
    '&::before': {
      left: 100,
    },
  },
}));

const FeatureCard = styled(Box)<{ theme?: Theme }>(({ theme }) => ({
  background: 'rgba(0, 255, 0, 0.15)',
  borderRadius: '8px',
  padding: theme?.spacing(6),
  textAlign: 'center',
  backdropFilter: 'blur(10px)',
  border: '1px solid rgba(0, 255, 0, 0.3)',
  transition: 'transform 0.3s ease',
  height: '300px',
  display: 'flex',
  flexDirection: 'column',
  justifyContent: 'center',
  alignItems: 'center',
  boxShadow: '0 0 20px rgba(0, 255, 0, 0.2)',
  '&:hover': {
    transform: 'translateY(-5px)',
    border: '1px solid rgba(0, 255, 0, 0.5)',
    boxShadow: '0 0 30px rgba(0, 255, 0, 0.3)',
  },
}));

const FeatureIcon = styled(Box)<{ theme?: Theme }>(({ theme }) => ({
  fontSize: '4rem',
  color: '#00ff00',
  marginBottom: theme?.spacing(3),
  filter: 'drop-shadow(0 0 10px rgba(0, 255, 0, 0.5))',
}));

const SectionTitle = styled(Typography)<{ theme?: Theme }>(({ theme }) => ({
  color: '#ffffff',
  fontSize: '2.5rem',
  fontWeight: 'bold',
  textAlign: 'center',
  marginBottom: theme?.spacing(6),
  textTransform: 'uppercase',
  letterSpacing: '0.1em',
  position: 'relative',
  textShadow: '0 0 15px rgba(0, 255, 0, 0.5)',
  '&::after': {
    content: '""',
    position: 'absolute',
    bottom: '-10px',
    left: '50%',
    transform: 'translateX(-50%)',
    width: '100px',
    height: '3px',
    background: 'linear-gradient(90deg, #00ff00, #00ffff)',
    boxShadow: '0 0 10px rgba(0, 255, 0, 0.5)',
  },
}));

const Signup: React.FC = () => {
  const navigate = useNavigate();
  const [showPassword, setShowPassword] = useState(false);
  const [formData, setFormData] = useState({
    username: '',
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
    // TODO: Implement signup logic
    navigate('/login');
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
              border: '1px solid rgba(255, 255, 255, 0.1)',
              borderRadius: 2,
              boxShadow: '0 0 20px rgba(0, 255, 255, 0.2)',
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
                startIcon={<Security />}
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
                SIGNUP
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