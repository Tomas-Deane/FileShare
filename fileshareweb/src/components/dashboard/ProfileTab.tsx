import React from 'react';
import {
  Box,
  Typography,
  Grid,
  Paper,
  Button,
} from '@mui/material';
import { Settings as SettingsIcon } from '@mui/icons-material';
import { DashboardCard } from './shared/DashboardCard';
import CyberButton from '../CyberButton';


interface ProfileData {
  username: string;
  email: string;
  storageUsed: string;
  storageLimit: string;
  lastLogin: string;
}

interface ProfileTabProps {
  profileData: ProfileData;
  onSettingsClick: () => void;
}

export const ProfileTab: React.FC<ProfileTabProps> = ({
  profileData,
  onSettingsClick,
}) => {
  return (
    <DashboardCard>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 3 }}>
        <Typography
          variant="h6"
          sx={{
            color: '#00ffff',
            textShadow: '0 0 10px rgba(0, 255, 0, 0.5)',
          }}
        >
          Profile
        </Typography>
        <CyberButton
          startIcon={<SettingsIcon />}
          onClick={onSettingsClick}
        >
          Settings
        </CyberButton>
      </Box>

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper
            sx={{
              p: 2,
              background: 'rgba(0, 0, 0, 0.5)',
              border: '1px solid rgba(0, 255, 0, 0.2)',
              borderRadius: 1,
            }}
          >
            <Typography
              sx={{
                color: '#00ffff',
                mb: 1,
                fontFamily: 'monospace',
              }}
            >
              Storage Usage
            </Typography>
            <Box sx={{ mb: 1 }}>
              <Typography
                sx={{
                  color: '#00ff00',
                  fontFamily: 'monospace',
                }}
              >
                {profileData.storageUsed} / {profileData.storageLimit}
              </Typography>
            </Box>
            <Box
              sx={{
                height: 8,
                background: 'rgba(0, 255, 0, 0.1)',
                borderRadius: 4,
                overflow: 'hidden',
              }}
            >
              <Box
                sx={{
                  height: '100%',
                  width: '25%',
                  background: 'linear-gradient(90deg, #00ff00, #00ffff)',
                  borderRadius: 4,
                }}
              />
            </Box>
          </Paper>
        </Grid>
        <Grid item xs={12} md={6}>
          <Paper
            sx={{
              p: 2,
              background: 'rgba(0, 0, 0, 0.5)',
              border: '1px solid rgba(0, 255, 0, 0.2)',
              borderRadius: 1,
            }}
          >
            <Typography
              sx={{
                color: '#00ffff',
                mb: 1,
                fontFamily: 'monospace',
              }}
            >
              Last Login
            </Typography>
            <Typography
              sx={{
                color: '#00ff00',
                fontFamily: 'monospace',
              }}
            >
              {profileData.lastLogin}
            </Typography>
          </Paper>
        </Grid>
      </Grid>
    </DashboardCard>
  );
};