import React from 'react';
import { styled } from '@mui/material/styles';
import { Button, Theme } from '@mui/material';

const StyledButton = styled(Button)<{ theme?: Theme }>(({ theme }) => ({
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

interface CyberButtonProps {
    children: React.ReactNode;
    onClick?: () => void;
}

const CyberButton: React.FC<CyberButtonProps> = ({ children, onClick, ...props }) => {
    return (
        <StyledButton onClick={onClick} {...props}>
            {children}
        </StyledButton>
    );
};

export default CyberButton;