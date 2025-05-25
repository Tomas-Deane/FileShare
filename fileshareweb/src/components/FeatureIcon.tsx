import React from 'react';
import { Box, BoxProps } from '@mui/material';
import { styled } from '@mui/material/styles';
import type { Theme } from '@mui/material/styles';

const StyledFeatureIcon = styled(Box)<{ theme?: Theme }>(({ theme }) => ({
  fontSize: '4rem',
  color: '#00ff00',
  marginBottom: theme?.spacing(3),
  filter: 'drop-shadow(0 0 10px rgba(0, 255, 0, 0.5))',
}));

interface FeatureIconProps extends BoxProps {
  children: React.ReactNode;
}

const FeatureIcon: React.FC<FeatureIconProps> = ({ children, ...props }) => {
  return (
    <StyledFeatureIcon {...props}>
      {children}
    </StyledFeatureIcon>
  );
};

export default FeatureIcon;