import React from 'react';
import { Box, BoxProps } from '@mui/material';
import { styled } from '@mui/material/styles';
import type { Theme } from '@mui/material/styles';

const StyledFeatureCard = styled(Box)<{ theme?: Theme }>(({ theme }) => ({
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

interface FeatureCardProps extends BoxProps {
  children: React.ReactNode;
}

const FeatureCard: React.FC<FeatureCardProps> = ({ children, ...props }) => {
  return (
    <StyledFeatureCard {...props}>
      {children}
    </StyledFeatureCard>
  );
};

export default FeatureCard;