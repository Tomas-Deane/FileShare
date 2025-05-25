import React from 'react';
import { Typography, TypographyProps } from '@mui/material';
import { styled } from '@mui/material/styles';
import type { Theme } from '@mui/material/styles';

const StyledSectionTitle = styled(Typography)<{ theme?: Theme }>(({ theme }) => ({
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

interface SectionTitleProps extends TypographyProps {
  children: React.ReactNode;
}

const SectionTitle: React.FC<SectionTitleProps> = ({ children, ...props }) => {
  return (
    <StyledSectionTitle variant="h2" {...props}>
      {children}
    </StyledSectionTitle>
  );
};

export default SectionTitle;