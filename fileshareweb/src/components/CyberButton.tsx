import React from 'react';
import { Button, ButtonProps } from '@mui/material';
import { styled } from '@mui/material/styles';
import type { Theme } from '@mui/material/styles';

const StyledCyberButton = styled(Button)<{ theme?: Theme }>(({ theme }) => ({
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
    background: 'linear-gradient(90deg, transparent, rgba(0, 255, 0, 0.2), transparent)',
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

export interface CyberButtonProps extends ButtonProps {
  children: React.ReactNode;
}

const CyberButton: React.FC<CyberButtonProps> = ({ children, ...props }) => {
  return (
    <StyledCyberButton {...props}>
      {children}
    </StyledCyberButton>
  );
};

export default CyberButton;