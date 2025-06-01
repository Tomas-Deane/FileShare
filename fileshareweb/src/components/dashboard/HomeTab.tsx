import React from 'react';
import { Box, Typography, Grid, Paper, List, ListItem, ListItemIcon, ListItemText } from '@mui/material';
import { FolderCopy as FolderIcon, PersonPin as PersonIcon } from '@mui/icons-material';
import { DashboardCard } from './shared/DashboardCard';

interface HomeTabProps {
  users: Array<{ id: number; username: string }>;
  files: Array<{
    id: number;
    name: string;
    type: string;
    size: string;
    date: Date;
  }>;
}

export const HomeTab: React.FC<HomeTabProps> = ({ users, files }) => {
  return (
    <>
      {/* Verified Users Section */}
      <DashboardCard sx={{ mb: 3 }}>
        <Typography variant="h6" sx={{ color: '#00ffff', mb: 2 }}>
          Users
        </Typography>
        <Grid container spacing={2}>
          {users.slice(0, 6).map((user) => (
            <Grid item xs={4} sm={2} key={user.id}>
              <Paper
                sx={{
                  p: 2,
                  textAlign: 'center',
                  background: 'rgba(0,0,0,0.6)',
                }}
              >
                <PersonIcon sx={{ fontSize: 32, color: '#00ff00' }} />
                <Typography sx={{ mt: 1, color: '#00ffff', fontSize: '0.875rem' }}>
                  {user.username}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </DashboardCard>

      {/* Recent Files Section */}
      <DashboardCard>
        <Typography variant="h6" sx={{ color: '#00ffff', mb: 2 }}>
          Recent Files
        </Typography>
        <List sx={{ maxHeight: 400, overflowY: 'auto' }}>
          {files
            .slice()
            .sort((a, b) => b.date.getTime() - a.date.getTime())
            .slice(0, 10)
            .map((f) => (
              <ListItem
                key={f.id}
                sx={{
                  mb: 1,
                  border: '1px solid rgba(0,255,0,0.2)',
                  borderRadius: 1,
                  transition: 'all 0.3s ease',
                  '&:hover': {
                    border: '1px solid rgba(0,255,0,0.4)',
                    backgroundColor: 'rgba(0,255,0,0.05)',
                    boxShadow: '0 0 20px rgba(0,255,0,0.2)',
                  },
                }}
              >
                <ListItemIcon>
                  <FolderIcon sx={{ color: '#00ff00' }} />
                </ListItemIcon>
                <ListItemText
                  primary={f.name}
                  secondary={`${f.type.toUpperCase()} • ${f.size} • ${f.date.toLocaleDateString('en-GB')} ${f.date.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })}`}
                  primaryTypographyProps={{
                    sx: { color: '#00ffff', fontWeight: 'bold' },
                  }}
                  secondaryTypographyProps={{
                    sx: { color: 'rgba(0,255,0,0.7)' },
                  }}
                />
              </ListItem>
            ))}
        </List>
      </DashboardCard>
    </>
  );
};