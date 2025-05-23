import React from 'react';
import { Button, ButtonProps } from '@mui/material';
import { styled } from '@mui/material/styles';
import type { Theme } from '@mui/material/styles';

const StyledNavButton = styled(Button)<{ theme?: Theme }>(({ theme }) => ({
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

interface NavButtonProps extends ButtonProps {
  children: React.ReactNode;
}

const NavButton: React.FC<NavButtonProps> = ({ children, ...props }) => {
  return (
    <StyledNavButton variant="outlined" {...props}>
      {children}
    </StyledNavButton>
  );
};

export default NavButton;