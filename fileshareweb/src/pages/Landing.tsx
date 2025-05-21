import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Box, Button, Container, Typography, AppBar, Toolbar, keyframes } from '@mui/material';
import { styled } from '@mui/material/styles';
import SecurityIcon from '@mui/icons-material/Security';
import SpeedIcon from '@mui/icons-material/Speed';
import StorageIcon from '@mui/icons-material/Storage';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import { SvgIconComponent } from '@mui/icons-material';
import type { Theme } from '@mui/material/styles';
import type { GridProps } from '@mui/material/Grid';

interface Feature {
  icon: React.ReactElement<SvgIconComponent>;
  title: string;
  description: string;
}

// Cyberpunk animations
const glitch = keyframes`
  0% {
    text-shadow: 0.05em 0 0 #00fffc, -0.03em -0.04em 0 #fc00ff,
                 0.025em 0.04em 0 #fffc00;
  }
  15% {
    text-shadow: 0.05em 0 0 #00fffc, -0.03em -0.04em 0 #fc00ff,
                 0.025em 0.04em 0 #fffc00;
  }
  16% {
    text-shadow: -0.05em -0.025em 0 #00fffc, 0.025em 0.035em 0 #fc00ff,
                 -0.05em -0.05em 0 #fffc00;
  }
  49% {
    text-shadow: -0.05em -0.025em 0 #00fffc, 0.025em 0.035em 0 #fc00ff,
                 -0.05em -0.05em 0 #fffc00;
  }
  50% {
    text-shadow: 0.05em 0.035em 0 #00fffc, 0.03em 0 0 #fc00ff,
                 0 -0.04em 0 #fffc00;
  }
  99% {
    text-shadow: 0.05em 0.035em 0 #00fffc, 0.03em 0 0 #fc00ff,
                 0 -0.04em 0 #fffc00;
  }
  100% {
    text-shadow: -0.05em 0 0 #00fffc, -0.025em -0.04em 0 #fc00ff,
                 -0.04em -0.025em 0 #fffc00;
  }
`;

const matrixRain = keyframes`
  0% {
    background-position: 0% 0%;
  }
  100% {
    background-position: 0% 100%;
  }
`;

const StyledContainer = styled(Container)<{ theme?: Theme }>(({ theme }) => ({
  minHeight: '100vh',
  display: 'flex',
  flexDirection: 'column',
  justifyContent: 'center',
  alignItems: 'center',
  background: 'linear-gradient(45deg, #000000 0%, #1a1a1a 100%)',
  position: 'relative',
  overflow: 'hidden',
  '&::before': {
    content: '""',
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    background: 'linear-gradient(180deg, rgba(0, 255, 0, 0.03) 0%, rgba(0, 255, 0, 0.01) 100%)',
    backgroundSize: '100% 20px',
    animation: `${matrixRain} 20s linear infinite`,
    pointerEvents: 'none',
    opacity: 0.3,
  },
  '&::after': {
    content: '""',
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    background: 'radial-gradient(circle at center, rgba(0, 0, 0, 0.2) 0%, rgba(0, 0, 0, 0.6) 100%)',
    pointerEvents: 'none',
  },
}));

const GlitchText = styled(Typography)<{ theme?: Theme }>(({ theme }) => ({
  color: '#ffffff',
  fontSize: '4rem',
  fontWeight: '900',
  textAlign: 'center',
  marginBottom: theme?.spacing(4),
  animation: `${glitch} 3s infinite`,
  textTransform: 'uppercase',
  letterSpacing: '0.2em',
  position: 'relative',
  textShadow: '0 0 20px rgba(33, 150, 243, 0.8)',
  '&::before, &::after': {
    content: 'attr(data-text)',
    position: 'absolute',
    top: 0,
    left: 0,
    width: '100%',
    height: '100%',
    opacity: 0.8,
  },
  '&::before': {
    left: '2px',
    textShadow: '-2px 0 #ff00c1',
    clip: 'rect(44px, 450px, 56px, 0)',
    animation: 'glitch-anim 5s infinite linear alternate-reverse',
  },
  '&::after': {
    left: '-2px',
    textShadow: '-2px 0 #00fff9',
    clip: 'rect(44px, 450px, 56px, 0)',
    animation: 'glitch-anim2 5s infinite linear alternate-reverse',
  },
}));

const CyberButton = styled(Button)<{ theme?: Theme }>(({ theme }) => ({
  background: 'linear-gradient(45deg, #2196F3 30%, #21CBF3 90%)',
  border: 0,
  borderRadius: 3,
  boxShadow: '0 3px 5px 2px rgba(33, 203, 243, .3)',
  color: 'white',
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
    background: 'linear-gradient(45deg, #21CBF3 30%, #2196F3 90%)',
    transform: 'scale(1.05)',
    '&::before': {
      left: 100,
    },
  },
}));

const FeatureCard = styled(Box)<{ theme?: Theme }>(({ theme }) => ({
  background: 'rgba(33, 150, 243, 0.15)',
  borderRadius: '8px',
  padding: theme?.spacing(6),
  textAlign: 'center',
  backdropFilter: 'blur(10px)',
  border: '1px solid rgba(33, 150, 243, 0.3)',
  transition: 'transform 0.3s ease',
  height: '300px',
  display: 'flex',
  flexDirection: 'column',
  justifyContent: 'center',
  alignItems: 'center',
  boxShadow: '0 0 20px rgba(33, 150, 243, 0.2)',
  '&:hover': {
    transform: 'translateY(-5px)',
    border: '1px solid rgba(33, 150, 243, 0.5)',
    boxShadow: '0 0 30px rgba(33, 150, 243, 0.3)',
  },
}));

const FeatureIcon = styled(Box)<{ theme?: Theme }>(({ theme }) => ({
  fontSize: '4rem',
  color: '#2196F3',
  marginBottom: theme?.spacing(3),
  filter: 'drop-shadow(0 0 10px rgba(33, 150, 243, 0.5))',
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
  textShadow: '0 0 15px rgba(33, 150, 243, 0.5)',
  '&::after': {
    content: '""',
    position: 'absolute',
    bottom: '-10px',
    left: '50%',
    transform: 'translateX(-50%)',
    width: '100px',
    height: '3px',
    background: 'linear-gradient(90deg, #2196F3, #21CBF3)',
    boxShadow: '0 0 10px rgba(33, 150, 243, 0.5)',
  },
}));

const StyledAppBar = styled(AppBar)<{ theme?: Theme }>(({ theme }) => ({
  background: 'rgba(0, 0, 0, 0.8)',
  backdropFilter: 'blur(10px)',
  borderBottom: '1px solid rgba(33, 150, 243, 0.2)',
  '&::before': {
    content: '""',
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    background: 'linear-gradient(90deg, transparent 0%, rgba(33, 150, 243, 0.1) 50%, transparent 100%)',
    animation: 'pulse 2s ease-in-out infinite',
  },
}));

const NavButton = styled(Button)<{ theme?: Theme }>(({ theme }) => ({
  color: '#2196F3',
  borderColor: '#2196F3',
  position: 'relative',
  overflow: 'hidden',
  '&::before': {
    content: '""',
    position: 'absolute',
    top: 0,
    left: -100,
    width: '100%',
    height: '100%',
    background: 'linear-gradient(90deg, transparent, rgba(33, 150, 243, 0.2), transparent)',
    transition: '0.5s',
  },
  '&:hover': {
    borderColor: '#21CBF3',
    color: '#21CBF3',
    background: 'rgba(33, 150, 243, 0.1)',
    '&::before': {
      left: 100,
    },
  },
}));

const features: Feature[] = [
  {
    icon: <SecurityIcon sx={{ fontSize: 40 }} />,
    title: 'End-to-End Encryption',
    description: 'Your files are encrypted with military-grade security, ensuring only you and your intended recipients can access them.',
  },
  {
    icon: <SpeedIcon sx={{ fontSize: 40 }} />,
    title: 'Lightning Fast',
    description: 'Experience blazing-fast upload and download speeds with our optimized peer-to-peer network.',
  },
  {
    icon: <StorageIcon sx={{ fontSize: 40 }} />,
    title: 'Decentralized Storage',
    description: 'Your files are distributed across a secure network, eliminating single points of failure.',
  },
  {
    icon: <CloudUploadIcon sx={{ fontSize: 40 }} />,
    title: 'Easy Sharing',
    description: 'Share files instantly with secure, time-limited links and granular access controls.',
  },
];

const Landing: React.FC = () => {
  const navigate = useNavigate();

  return (
    <>
      <StyledAppBar position="fixed" elevation={0}>
        <Toolbar>
          <Typography 
            variant="h6" 
            component="div" 
            sx={{ 
              flexGrow: 1,
              color: '#2196F3',
              fontWeight: 'bold',
              letterSpacing: '0.1em',
              textShadow: '0 0 10px rgba(33, 150, 243, 0.5)',
            }}
          >
            FileShare
          </Typography>
          <NavButton 
            variant="outlined"
            onClick={() => navigate('/login')}
          >
            Login
          </NavButton>
        </Toolbar>
      </StyledAppBar>
      <Toolbar /> {/* Spacer for fixed AppBar */}
      <StyledContainer maxWidth={false}>
        {/* Hero Section */}
        <Box sx={{ textAlign: 'center', mb: 8, mt: 4, position: 'relative', zIndex: 1 }}>
          <GlitchText variant="h1">
            FileShare
          </GlitchText>
          <Typography 
            variant="h5" 
            sx={{ 
              mb: 4, 
              textAlign: 'center',
              color: '#2196F3',
              fontWeight: '800',
              textShadow: '0 0 15px rgba(33, 150, 243, 0.6)',
              letterSpacing: '0.1em',
            }}
          >
            Secure. Fast. Decentralized.
          </Typography>
          <Typography 
            variant="h6" 
            sx={{ 
              mb: 6, 
              maxWidth: '600px', 
              mx: 'auto',
              color: '#ffffff',
              fontWeight: '600',
              textShadow: '0 0 10px rgba(255, 255, 255, 0.5)',
              lineHeight: 1.6,
            }}
          >
            Experience the future of file sharing with our cutting-edge decentralized platform.
            Built for security, speed, and reliability.
          </Typography>
          <CyberButton onClick={() => navigate('/signup')}>
            Get Started
          </CyberButton>
        </Box>

        {/* Features Section */}
        <Box sx={{ width: '100%', py: 8, px: 2, position: 'relative', zIndex: 1 }}>
          <SectionTitle variant="h2">
            Features
          </SectionTitle>
          <Box sx={{ 
            display: 'grid', 
            gridTemplateColumns: 'repeat(2, 1fr)', 
            gap: 4,
            maxWidth: '1000px',
            mx: 'auto',
            '& > *': {
              width: '100%',
            }
          }}>
            {features.map((feature) => (
              <FeatureCard key={feature.title}>
                <FeatureIcon>
                  {feature.icon}
                </FeatureIcon>
                <Typography variant="h5" color="primary" gutterBottom sx={{ fontWeight: 'bold', textShadow: '0 0 10px rgba(33, 150, 243, 0.3)' }}>
                  {feature.title}
                </Typography>
                <Typography variant="body1" sx={{ color: '#ffffff', textShadow: '0 0 5px rgba(255, 255, 255, 0.2)' }}>
                  {feature.description}
                </Typography>
              </FeatureCard>
            ))}
          </Box>
        </Box>
      </StyledContainer>
    </>
  );
};

export default Landing; 