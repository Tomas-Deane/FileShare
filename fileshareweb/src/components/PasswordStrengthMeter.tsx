import React from 'react';
import { Box, LinearProgress, Typography } from '@mui/material';
import zxcvbn from 'zxcvbn';

interface PasswordStrengthMeterProps {
  password: string;
}

const PasswordStrengthMeter: React.FC<PasswordStrengthMeterProps> = ({ password }) => {
  const result = zxcvbn(password);
  const strength = result.score; // 0-4
  const feedback = result.feedback.warning || result.feedback.suggestions[0] || '';

  const getColor = (score: number) => {
    switch (score) {
      case 0:
        return '#ff1744'; // Red
      case 1:
        return '#ff9100'; // Orange
      case 2:
        return '#ffd600'; // Yellow
      case 3:
        return '#00e676'; // Light Green
      case 4:
        return '#00c853'; // Green
      default:
        return '#ff1744';
    }
  };

  const getStrengthText = (score: number) => {
    switch (score) {
      case 0:
        return 'Very Weak';
      case 1:
        return 'Weak';
      case 2:
        return 'Fair';
      case 3:
        return 'Strong';
      case 4:
        return 'Very Strong';
      default:
        return 'Very Weak';
    }
  };

  return (
    <Box sx={{ width: '100%', mt: 1 }}>
      <LinearProgress
        variant="determinate"
        value={(strength / 4) * 100}
        sx={{
          height: 8,
          borderRadius: 4,
          backgroundColor: 'rgba(0, 255, 0, 0.1)',
          '& .MuiLinearProgress-bar': {
            backgroundColor: getColor(strength),
            borderRadius: 4,
          },
        }}
      />
      <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 0.5 }}>
        <Typography
          variant="caption"
          sx={{
            color: getColor(strength),
            fontFamily: 'monospace',
          }}
        >
          {getStrengthText(strength)}
        </Typography>
        {feedback && (
          <Typography
            variant="caption"
            sx={{
              color: '#00ffff',
              fontFamily: 'monospace',
              textAlign: 'right',
            }}
          >
            {feedback}
          </Typography>
        )}
      </Box>
    </Box>
  );
};

export default PasswordStrengthMeter; 