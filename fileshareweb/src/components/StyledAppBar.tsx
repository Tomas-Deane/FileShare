import React from 'react';
import { AppBar, AppBarProps } from '@mui/material';
import { styled } from '@mui/material/styles';
import type { Theme } from '@mui/material/styles';

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

export interface CyberAppBarProps extends AppBarProps {
  children: React.ReactNode;
}

const CyberAppBar: React.FC<CyberAppBarProps> = ({ children, ...props }) => {
  return (
    <StyledAppBar position="static" {...props}>
      {children}
    </StyledAppBar>
  );
};

export default CyberAppBar;