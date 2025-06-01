import React from 'react';
import {
  Grid,
  Box,
  Typography,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Button,
  Alert,
  IconButton,
  InputAdornment,
} from '@mui/material';
import {
  PersonPin as PersonIcon,
  VerifiedUser as VerifiedUserIcon,
  Search as SearchIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { DashboardCard } from './shared/DashboardCard';
import { SearchField } from './shared/SearchField';

interface UserData {
  id: number;
  username: string;
}

interface VerifiedUser {
  username: string;
  verifiedAt: string;
}

interface UsersTabProps {
  users: UserData[];
  verifiedUsers: VerifiedUser[];
  loadingUsers: boolean;
  userError: string | null;
  userSearchQuery: string;
  onUserSearchChange: (query: string) => void;
  onVerifyClick: (user: UserData) => void;
  onRefreshVerifiedUsers: () => void;
}

export const UsersTab: React.FC<UsersTabProps> = ({
  users,
  verifiedUsers,
  loadingUsers,
  userError,
  userSearchQuery,
  onUserSearchChange,
  onVerifyClick,
  onRefreshVerifiedUsers,
}) => {
  return (
    <Grid container spacing={3}>
      {/* Search Users Card */}
      <Grid item xs={12} md={6}>
        <DashboardCard>
          <Box sx={{ mb: 3 }}>
            <Typography
              variant="h6"
              sx={{
                color: '#00ffff',
                textShadow: '0 0 10px rgba(0, 255, 0, 0.5)',
                mb: 2,
              }}
            >
              Search Users
            </Typography>
            <SearchField
              fullWidth
              placeholder="Search users..."
              value={userSearchQuery}
              onChange={(e) => onUserSearchChange(e.target.value)}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon sx={{ color: '#00ff00' }} />
                  </InputAdornment>
                ),
              }}
            />
          </Box>
          {loadingUsers ? (
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <Typography sx={{ color: '#00ff00' }}>Loading users...</Typography>
            </Box>
          ) : userError ? (
            <Alert severity="error" sx={{ bgcolor: 'rgba(255, 0, 0, 0.1)' }}>
              {userError}
            </Alert>
          ) : users.length === 0 ? (
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <Typography sx={{ color: '#00ff00' }}>
                {userSearchQuery ? 'No users found.' : 'Start typing to search users...'}
              </Typography>
            </Box>
          ) : (
            <List>
              {users.map((user) => (
                <ListItem
                  key={user.id}
                  sx={{
                    border: '1px solid rgba(0, 255, 0, 0.2)',
                    borderRadius: 1,
                    mb: 1,
                    display: 'flex',
                    alignItems: 'center',
                    '&:hover': {
                      border: '1px solid rgba(0, 255, 0, 0.4)',
                      backgroundColor: 'rgba(0, 255, 0, 0.05)',
                    },
                  }}
                >
                  <ListItemIcon>
                    <PersonIcon sx={{ color: '#00ff00' }} />
                  </ListItemIcon>
                  <ListItemText
                    primary={user.username}
                    primaryTypographyProps={{
                      sx: { color: '#00ffff', fontWeight: 'bold' },
                    }}
                  />
                  <Box sx={{ ml: 'auto' }}>
                    <Button
                      variant="contained"
                      color="primary"
                      onClick={() => onVerifyClick(user)}
                      size="small"
                      sx={{ minWidth: 100, fontSize: '0.95rem', height: 36, px: 2.5, py: 1 }}
                    >
                      Verify
                    </Button>
                  </Box>
                </ListItem>
              ))}
            </List>
          )}
        </DashboardCard>
      </Grid>

      {/* Verified Users Card */}
      <Grid item xs={12} md={6}>
        <DashboardCard>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography
              variant="h6"
              sx={{
                color: '#00ffff',
                textShadow: '0 0 10px rgba(0, 255, 0, 0.5)',
              }}
            >
              Verified Users
            </Typography>
            <IconButton 
              onClick={onRefreshVerifiedUsers}
              sx={{ color: '#00ff00' }}
            >
              <RefreshIcon />
            </IconButton>
          </Box>
          {verifiedUsers.length === 0 ? (
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <Typography sx={{ color: '#00ff00' }}>
                No verified users yet. Search and verify users to start sharing files.
              </Typography>
            </Box>
          ) : (
            <List>
              {verifiedUsers.map((user) => (
                <ListItem
                  key={user.username}
                  sx={{
                    border: '1px solid rgba(0, 255, 0, 0.2)',
                    borderRadius: 1,
                    mb: 1,
                    '&:hover': {
                      border: '1px solid rgba(0, 255, 0, 0.4)',
                      backgroundColor: 'rgba(0, 255, 0, 0.05)',
                    },
                  }}
                >
                  <ListItemIcon>
                    <VerifiedUserIcon sx={{ color: '#00ff00' }} />
                  </ListItemIcon>
                  <ListItemText
                    primary={user.username}
                    secondary={`Verified on ${new Date(user.verifiedAt).toLocaleDateString()}`}
                    primaryTypographyProps={{
                      sx: { color: '#00ffff', fontWeight: 'bold' },
                    }}
                    secondaryTypographyProps={{
                      sx: { color: 'rgba(0, 255, 0, 0.7)' },
                    }}
                  />
                </ListItem>
              ))}
            </List>
          )}
        </DashboardCard>
      </Grid>
    </Grid>
  );
};