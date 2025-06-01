import React from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Box,
} from '@mui/material';
import CyberButton from '../../../CyberButton';

interface ProfileData {
  username: string;
  email: string;
  storageUsed: string;
  storageLimit: string;
  lastLogin: string;
}

interface ProfileSettingsDialogProps {
  open: boolean;
  onClose: () => void;
  profileData: ProfileData;
  editMode: boolean;
  editedProfile: ProfileData;
  onEdit: () => void;
  onCancel: () => void;
  onSave: () => void;
  onProfileChange: (field: keyof ProfileData, value: string) => void;
}

export const ProfileSettingsDialog: React.FC<ProfileSettingsDialogProps> = ({
  open,
  onClose,
  profileData,
  editMode,
  editedProfile,
  onEdit,
  onCancel,
  onSave,
  onProfileChange,
}) => {
  return (
    <Dialog
      open={open}
      onClose={onClose}
      PaperProps={{
        sx: {
          background: 'rgba(0, 0, 0, 0.9)',
          border: '1px solid rgba(0, 255, 0, 0.2)',
          color: '#00ff00',
          minWidth: '400px',
        },
      }}
    >
      <DialogTitle sx={{ color: '#00ffff', borderBottom: '1px solid rgba(0, 255, 0, 0.2)' }}>
        Profile Settings
      </DialogTitle>
      <DialogContent sx={{ mt: 2 }}>
        <Box sx={{ mb: 3 }}>
          <TextField
            fullWidth
            label="Username"
            value={editMode ? editedProfile.username : profileData.username}
            onChange={(e) => onProfileChange('username', e.target.value)}
            disabled={!editMode}
            sx={{
              mb: 2,
              '& .MuiOutlinedInput-root': {
                '& fieldset': {
                  borderColor: 'rgba(0, 255, 0, 0.3)',
                },
                '&:hover fieldset': {
                  borderColor: 'rgba(0, 255, 0, 0.5)',
                },
                '&.Mui-focused fieldset': {
                  borderColor: '#00ff00',
                },
              },
              '& .MuiInputLabel-root': {
                color: 'rgba(0, 255, 0, 0.7)',
              },
              '& .MuiInputBase-input': {
                color: '#fff',
              },
            }}
          />

          <TextField
            fullWidth
            label="Email"
            value={editMode ? editedProfile.email : profileData.email}
            onChange={(e) => onProfileChange('email', e.target.value)}
            disabled={!editMode}
            sx={{
              mb: 2,
              '& .MuiOutlinedInput-root': {
                '& fieldset': {
                  borderColor: 'rgba(0, 255, 0, 0.3)',
                },
                '&:hover fieldset': {
                  borderColor: 'rgba(0, 255, 0, 0.5)',
                },
                '&.Mui-focused fieldset': {
                  borderColor: '#00ff00',
                },
              },
              '& .MuiInputLabel-root': {
                color: 'rgba(0, 255, 0, 0.7)',
              },
              '& .MuiInputBase-input': {
                color: '#fff',
              },
            }}
          />

          <TextField
            fullWidth
            label="New Password"
            type="password"
            disabled={!editMode}
            sx={{
              mb: 2,
              '& .MuiOutlinedInput-root': {
                '& fieldset': {
                  borderColor: 'rgba(0, 255, 0, 0.3)',
                },
                '&:hover fieldset': {
                  borderColor: 'rgba(0, 255, 0, 0.5)',
                },
                '&.Mui-focused fieldset': {
                  borderColor: '#00ff00',
                },
              },
              '& .MuiInputLabel-root': {
                color: 'rgba(0, 255, 0, 0.7)',
              },
              '& .MuiInputBase-input': {
                color: '#fff',
              },
            }}
          />
        </Box>
      </DialogContent>
      <DialogActions sx={{ borderTop: '1px solid rgba(0, 255, 0, 0.2)', p: 2 }}>
        <Button
          onClick={onClose}
          sx={{ color: 'rgba(0, 255, 0, 0.7)' }}
        >
          Cancel
        </Button>
        {editMode ? (
          <>
            <Button
              onClick={onCancel}
              sx={{ color: 'rgba(255, 0, 0, 0.7)' }}
            >
              Cancel Edit
            </Button>
            <CyberButton onClick={onSave}>
              Save Changes
            </CyberButton>
          </>
        ) : (
          <CyberButton onClick={onEdit}>
            Edit Profile
          </CyberButton>
        )}
      </DialogActions>
    </Dialog>
  );
};