import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Box, Button, Container, Typography, AppBar, Toolbar, keyframes } from '@mui/material';
import Grid from '@mui/material/Grid';

import { styled } from '@mui/material/styles';
import SecurityIcon from '@mui/icons-material/Security';
import SpeedIcon from '@mui/icons-material/Speed';
import StorageIcon from '@mui/icons-material/Storage';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import PeopleIcon from '@mui/icons-material/People';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import StarIcon from '@mui/icons-material/Star';
import { SvgIconComponent } from '@mui/icons-material';
import type { Theme } from '@mui/material/styles';
import { 
  CyberButton, 
  CyberAppBar, 
  NavButton, 
  SectionTitle, 
  FeatureCard, 
  FeatureIcon,
  MatrixBackground 
} from '../components';

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
  justifyContent: 'flex-start',
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
    background: 'linear-gradient(180deg, rgba(0, 255, 0, 0.08) 0%, rgba(0, 255, 0, 0.03) 100%)',
    backgroundSize: '100% 20px',
    animation: `${matrixRain} 20s linear infinite`,
    pointerEvents: 'none',
    opacity: 0.5,
  },
  '&::after': {
    content: '""',
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    background: 'radial-gradient(circle at center, rgba(0, 0, 0, 0.15) 0%, rgba(0, 0, 0, 0.7) 100%)',
    pointerEvents: 'none',
  },
}));

const GlitchText = styled(Typography)<{ theme?: Theme }>(({ theme }) => ({
  color: '#ffffff',
  fontSize: '3rem',
  fontWeight: '900',
  textAlign: 'center',
  marginBottom: theme?.spacing(4),
  animation: `${glitch} 3s infinite`,
  textTransform: 'uppercase',
  letterSpacing: '0.2em',
  position: 'relative',
  textShadow: '0 0 25px rgba(0, 255, 0, 0.9)',
  '&::before, &::after': {
    content: 'attr(data-text)',
    position: 'absolute',
    top: 0,
    left: 0,
    width: '100%',
    height: '100%',
    opacity: 0.9,
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

const FeatureCard = styled(Box)<{ theme?: Theme }>(({ theme }) => ({
  background: 'rgba(0, 255, 0, 0.12)',
  borderRadius: '8px',
  padding: theme?.spacing(6),
  textAlign: 'center',
  backdropFilter: 'blur(10px)',
  border: '1px solid rgba(0, 255, 0, 0.25)',
  transition: 'transform 0.3s ease',
  height: '300px',
  display: 'flex',
  flexDirection: 'column',
  justifyContent: 'center',
  alignItems: 'center',
  boxShadow: '0 0 20px rgba(0, 255, 0, 0.15)',
  '&:hover': {
    transform: 'translateY(-5px)',
    border: '1px solid rgba(0, 255, 0, 0.35)',
    boxShadow: '0 0 25px rgba(0, 255, 0, 0.2)',
  },
}));

const FeatureIcon = styled(Box)<{ theme?: Theme }>(({ theme }) => ({
  fontSize: '4rem',
  color: '#00ff00',
  marginBottom: theme?.spacing(3),
  filter: 'drop-shadow(0 0 8px rgba(0, 255, 0, 0.4))',
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
  borderColor: 'rgba(0, 255, 0, 0.5)',
  position: 'relative',
  overflow: 'hidden',
  '&::before': {
    content: '""',
    position: 'absolute',
    top: 0,
    left: -100,
    width: '100%',
    height: '100%',
    background: 'linear-gradient(90deg, transparent, rgba(0, 255, 0, 0.15), transparent)',
    transition: '0.5s',
  },
  '&:hover': {
    borderColor: 'rgba(0, 255, 255, 0.6)',
    color: '#00ffff',
    background: 'rgba(0, 255, 0, 0.08)',
    '&::before': {
      left: 100,
    },
  },
}));

const TestimonialCard = styled(Box)<{ theme?: Theme }>(({ theme }) => ({
  background: 'rgba(0, 255, 0, 0.15)',
  borderRadius: '8px',
  padding: theme?.spacing(4),
  textAlign: 'left',
  backdropFilter: 'blur(10px)',
  border: '1px solid rgba(0, 255, 0, 0.3)',
  height: '280px',
  display: 'flex',
  flexDirection: 'column',
  boxShadow: '0 0 25px rgba(0, 255, 0, 0.2)',
  '&:hover': {
    border: '1px solid rgba(0, 255, 0, 0.5)',
    boxShadow: '0 0 35px rgba(0, 255, 0, 0.3)',
  },
}));

const StatCard = styled(Box)<{ theme?: Theme }>(({ theme }) => ({
  background: 'rgba(0, 255, 0, 0.08)',
  borderRadius: '8px',
  padding: theme?.spacing(3),
  textAlign: 'center',
  backdropFilter: 'blur(10px)',
  border: '1px solid rgba(0, 255, 0, 0.3)',
  transition: 'transform 0.3s ease',
  height: '160px',
  display: 'flex',
  flexDirection: 'column',
  justifyContent: 'center',
  alignItems: 'center',
  boxShadow: '0 0 20px rgba(0, 255, 0, 0.15)',
  '&:hover': {
    transform: 'translateY(-5px)',
    border: '1px solid rgba(0, 255, 0, 0.5)',
    boxShadow: '0 0 30px rgba(0, 255, 0, 0.25)',
  },
}));

const CTASection = styled(Box)<{ theme?: Theme }>(({ theme }) => ({
  position: 'relative',
  background: 'none',
  borderRadius: '0',
  padding: theme?.spacing(8),
  textAlign: 'center',
  marginTop: theme?.spacing(8),
  overflow: 'visible',
  zIndex: 2,
  display: 'flex',
  flexDirection: 'column',
  alignItems: 'center',
  justifyContent: 'center',
  minHeight: '340px',
}));

// Geometric background for CTA
const GeometricBg = styled('div')<{}>(() => ({
  position: 'absolute',
  top: 0,
  left: '50%',
  transform: 'translateX(-50%)',
  width: '100%',
  height: '100%',
  zIndex: 0,
  pointerEvents: 'none',
  overflow: 'visible',
  '& svg': {
    display: 'block',
    width: '100%',
    height: '100%',
  },
}));

const Footer = styled(Box)<{ theme?: Theme }>(({ theme }) => ({
  background: 'rgba(0, 0, 0, 0.92)',
  borderTop: '1px solid rgba(0, 255, 0, 0.2)',
  padding: theme?.spacing(4),
  width: '100%',
  position: 'relative',
  marginTop: theme?.spacing(8),
  '&::before': {
    content: '""',
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    height: '1px',
    background: 'linear-gradient(90deg, transparent, rgba(0, 255, 0, 0.3), transparent)',
  }
}));

const FooterLink = styled(Typography)<{ theme?: Theme }>(({ theme }) => ({
  color: 'rgba(255, 255, 255, 0.7)',
  cursor: 'pointer',
  transition: 'all 0.3s ease',
  '&:hover': {
    color: '#00ff00',
    textShadow: '0 0 8px rgba(0, 255, 0, 0.5)',
  }
}));

const features: Feature[] = [
  {
    icon: <SecurityIcon sx={{ fontSize: 40 }} />,
    title: 'Zero-Trust Architecture',
    description: 'Built on a zero-trust model where every request is verified, authenticated, and encrypted, regardless of origin or network.',
  },
  {
    icon: <SpeedIcon sx={{ fontSize: 40 }} />,
    title: 'X3DH Protocol',
    description: 'Implements the Extended Triple Diffie-Hellman protocol for perfect forward secrecy and secure key exchange.',
  },
  {
    icon: <StorageIcon sx={{ fontSize: 40 }} />,
    title: 'Argon2id Security',
    description: 'Uses Argon2id, the winner of the 2015 Password Hashing Competition, for memory-hard password hashing.',
  },
  {
    icon: <CloudUploadIcon sx={{ fontSize: 40 }} />,
    title: 'Secure Sharing',
    description: 'End-to-end encrypted file sharing with granular access controls and automatic key rotation.',
  },
];

const testimonials = [
  {
    name: "Dr. Sarah Chen",
    role: "Security Researcher",
    content: "The implementation of X3DH and zero-trust architecture sets a new standard for secure file sharing. The perfect forward secrecy is particularly impressive.",
    rating: 5
  },
  {
    name: "Michael Rodriguez",
    role: "DevOps Engineer",
    content: "The zero-trust model combined with Argon2id hashing provides enterprise-grade security while maintaining excellent performance.",
    rating: 5
  },
  {
    name: "Emma Thompson",
    role: "Security Architect",
    content: "The combination of X3DH for key exchange and zero-trust architecture creates an exceptionally secure platform for sensitive data sharing.",
    rating: 5
  }
];

const statistics = [
  { value: "256-bit", label: "AES Encryption" },
  { value: "99.99%", label: "Uptime SLA" },
  { value: "< 50ms", label: "Key Exchange" },
  { value: "Zero", label: "Data Breaches" }
];

const Landing: React.FC = () => {
  const navigate = useNavigate();

  return (
    <>
      <MatrixBackground />
      <CyberAppBar position="fixed" elevation={0}>
        <Toolbar>
          <Typography 
            variant="h6" 
            component="div" 
            sx={{ 
              flexGrow: 1,
              color: '#00ff00',
              fontWeight: 'bold',
              letterSpacing: '0.1em',
              textShadow: '0 0 10px rgba(0, 255, 0, 0.5)',
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
      </CyberAppBar>
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
              color: '#00ff00',
              fontWeight: '800',
              textShadow: '0 0 15px rgba(0, 255, 0, 0.6)',
              letterSpacing: '0.1em',
              fontSize: '1.5rem',
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
              fontSize: '1.1rem',
            }}
          >
            Experience the future of secure file sharing with our zero-trust platform.
            Powered by X3DH protocol and Argon2id security, ensuring your data remains protected at every step.
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
                <Typography 
                  variant="h5" 
                  gutterBottom 
                  sx={{ 
                    fontWeight: 'bold', 
                    color: '#00ffff',
                    textShadow: '0 0 10px rgba(0, 255, 255, 0.3)',
                    letterSpacing: '0.05em',
                    fontSize: '1.2rem',
                  }}
                >
                  {feature.title}
                </Typography>
                <Typography 
                  variant="body1" 
                  sx={{ 
                    color: '#ffffff', 
                    textShadow: '0 0 5px rgba(255, 255, 255, 0.2)',
                    fontSize: '0.9rem',
                  }}
                >
                  {feature.description}
                </Typography>
              </FeatureCard>
            ))}
          </Box>
        </Box>

        {/* Statistics Section */}
        <Box sx={{ width: '100%', py: 8, px: 2, position: 'relative', zIndex: 1 }}>
          <SectionTitle variant="h2">
            By The Numbers
          </SectionTitle>
          <Grid container component="div" spacing={4} sx={{ maxWidth: '1000px', mx: 'auto', justifyContent: 'center' }}>
            {statistics.map((stat) => (
              <Grid item component="div" xs={6} md={3} key={stat.label} sx={{ display: 'flex', justifyContent: 'center' }}>
                <StatCard>
                  <Typography 
                    variant="h3" 
                    sx={{ 
                      color: '#00ff00',
                      fontWeight: 'bold',
                      mb: 1,
                      textShadow: '0 0 10px rgba(0, 255, 0, 0.3)'
                    }}
                  >
                    {stat.value}
                  </Typography>
                  <Typography 
                    variant="h6" 
                    sx={{ 
                      color: '#ffffff',
                      textShadow: '0 0 5px rgba(255, 255, 255, 0.2)'
                    }}
                  >
                    {stat.label}
                  </Typography>
                </StatCard>
              </Grid>
            ))}
          </Grid>
        </Box>

        {/* Testimonials Section */}
        <Box sx={{ width: '100%', py: 8, px: 2, position: 'relative', zIndex: 1 }}>
          <SectionTitle variant="h2">
            What Our Users Say
          </SectionTitle>
          <Grid container component="div" spacing={4} sx={{ maxWidth: '1000px', mx: 'auto', justifyContent: 'center' }}>
            {testimonials.map((testimonial) => (
              <Grid item component="div" xs={12} md={4} key={testimonial.name} sx={{ display: 'flex', justifyContent: 'center' }}>
                <TestimonialCard>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    <PeopleIcon sx={{ color: '#00ff00', mr: 1 }} />
                    <Box>
                      <Typography 
                        variant="h6" 
                        sx={{ 
                          color: '#00ffff',
                          fontWeight: 'bold'
                        }}
                      >
                        {testimonial.name}
                      </Typography>
                      <Typography 
                        variant="body2" 
                        sx={{ 
                          color: '#ffffff',
                          opacity: 0.8
                        }}
                      >
                        {testimonial.role}
                      </Typography>
                    </Box>
                  </Box>
                  <Typography 
                    variant="body1" 
                    sx={{ 
                      color: '#ffffff',
                      mb: 2,
                      flexGrow: 1,
                      overflow: 'hidden',
                      display: '-webkit-box',
                      WebkitLineClamp: 4,
                      WebkitBoxOrient: 'vertical'
                    }}
                  >
                    "{testimonial.content}"
                  </Typography>
                  <Box sx={{ display: 'flex' }}>
                    {[...Array(testimonial.rating)].map((_, i) => (
                      <StarIcon 
                        key={i} 
                        sx={{ 
                          color: '#00ff00',
                          fontSize: '1.2rem'
                        }} 
                      />
                    ))}
                  </Box>
                </TestimonialCard>
              </Grid>
            ))}
          </Grid>
        </Box>

        {/* Call to Action Section */}
        <Box sx={{ width: '100%', py: 8, px: 2, position: 'relative', zIndex: 1 }}>
          <CTASection>
            <GeometricBg>
              <svg width="100%" height="340" viewBox="0 0 1000 340" preserveAspectRatio="none">
                <polygon points="0,0 1000,0 900,340 100,340" fill="rgba(0,255,0,0.10)" />
                <polygon points="100,0 900,0 800,340 200,340" fill="rgba(0,255,255,0.10)" />
                <polygon points="250,0 750,0 700,340 300,340" fill="rgba(0,255,0,0.18)" />
                <polygon points="400,0 600,0 580,340 420,340" fill="rgba(0,255,255,0.18)" />
              </svg>
            </GeometricBg>
            <Typography 
              variant="h3" 
              sx={{ 
                color: '#00ff00',
                fontWeight: 'bold',
                mb: 3,
                textShadow: '0 0 15px rgba(0, 255, 0, 0.5)',
                zIndex: 2,
                position: 'relative',
                letterSpacing: '0.05em',
                textTransform: 'uppercase',
              }}
            >
              Ready to Experience Secure File Sharing?
            </Typography>
            <Typography 
              variant="h6" 
              sx={{ 
                color: '#ffffff',
                mb: 4,
                maxWidth: '600px',
                mx: 'auto',
                zIndex: 2,
                position: 'relative',
                fontWeight: 500,
                textShadow: '0 0 8px #00ff00',
              }}
            >
              Join thousands of users who trust FileShare for their secure file sharing needs. Get started today and experience the future of file sharing.
            </Typography>
            <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', zIndex: 2, position: 'relative' }}>
              <CyberButton onClick={() => navigate('/signup')} sx={{ borderRadius: '0 24px 0 24px', fontWeight: 700, fontSize: '1.2rem', px: 5 }}>
                Get Started
              </CyberButton>
              <NavButton 
                variant="outlined"
                onClick={() => navigate('/login')}
                sx={{ borderRadius: '24px 0 24px 0', fontWeight: 700, fontSize: '1.2rem', px: 5 }}
              >
                Learn More
              </NavButton>
            </Box>
          </CTASection>
        </Box>

        {/* Footer */}
        <Footer>
          <Container maxWidth="lg">
            <Grid container component="div" spacing={4} justifyContent="space-between">
              <Grid item component="div" xs={12} md={4}>
                <Typography 
                  variant="h6" 
                  sx={{ 
                    color: '#00ff00',
                    fontWeight: 'bold',
                    mb: 2,
                    textShadow: '0 0 10px rgba(0, 255, 0, 0.3)'
                  }}
                >
                  Network Risk Mitigation Corp
                </Typography>
                <Typography 
                  variant="body2" 
                  sx={{ 
                    color: 'rgba(255, 255, 255, 0.7)',
                    mb: 2,
                    maxWidth: '300px'
                  }}
                >
                  Securing the future of digital communication through advanced encryption and zero-trust architecture.
                </Typography>
              </Grid>
              <Grid item component="div" xs={12} md={3}>
                <Typography 
                  variant="subtitle1" 
                  sx={{ 
                    color: '#00ff00',
                    fontWeight: 'bold',
                    mb: 2
                  }}
                >
                  Quick Links
                </Typography>
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                  <FooterLink variant="body2" onClick={() => navigate('/about')}>
                    About Us
                  </FooterLink>
                  <FooterLink variant="body2" onClick={() => navigate('/security')}>
                    Security
                  </FooterLink>
                  <FooterLink variant="body2" onClick={() => navigate('/contact')}>
                    Contact
                  </FooterLink>
                </Box>
              </Grid>
              <Grid item component="div" xs={12} md={3}>
                <Typography 
                  variant="subtitle1" 
                  sx={{ 
                    color: '#00ff00',
                    fontWeight: 'bold',
                    mb: 2
                  }}
                >
                  Legal
                </Typography>
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                  <FooterLink variant="body2" onClick={() => navigate('/privacy')}>
                    Privacy Policy
                  </FooterLink>
                  <FooterLink variant="body2" onClick={() => navigate('/terms')}>
                    Terms of Service
                  </FooterLink>
                  <FooterLink variant="body2" onClick={() => navigate('/compliance')}>
                    Compliance
                  </FooterLink>
                </Box>
              </Grid>
            </Grid>
            <Box 
              sx={{ 
                mt: 4, 
                pt: 2, 
                borderTop: '1px solid rgba(0, 255, 0, 0.1)',
                textAlign: 'center'
              }}
            >
              <Typography 
                variant="body2" 
                sx={{ 
                  color: 'rgba(255, 255, 255, 0.5)'
                }}
              >
                © {new Date().getFullYear()} Network Risk Mitigation Corp. All rights reserved.
              </Typography>
            </Box>
          </Container>
        </Footer>
      </StyledContainer>
    </>
  );
};

export default Landing; 