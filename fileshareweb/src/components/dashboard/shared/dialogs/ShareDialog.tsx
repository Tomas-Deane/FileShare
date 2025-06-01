import React from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Typography,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Checkbox,
  Alert,
  Box,
} from '@mui/material';
import { VerifiedUser as VerifiedUserIcon } from '@mui/icons-material';
import CyberButton from '../../../CyberButton';

interface RecipientKeyBundle {
  data: {
    IK_pub: string;
    SPK_pub: string;
    SPK_signature: string;
  };
  verified: boolean;
  lastVerified: string;
}

interface ShareDialogProps {
  open: boolean;
  onClose: () => void;
  selectedRecipients: string[];
  onRecipientsChange: (recipients: string[]) => void;
  onShare: () => void;
  verifiedRecipients: { [username: string]: RecipientKeyBundle };
}

export const ShareDialog: React.FC<ShareDialogProps> = ({
  open,
  onClose,
  selectedRecipients,
  onRecipientsChange,
  onShare,
  verifiedRecipients,
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
        },
      }}
    >
      <DialogTitle sx={{ color: '#00ffff', borderBottom: '1px solid rgba(0, 255, 0, 0.2)' }}>
        Share File
      </DialogTitle>
      <DialogContent sx={{ mt: 2 }}>
        <Typography
          variant="subtitle1"
          sx={{
            color: '#00ffff',
            mb: 2,
            fontFamily: 'monospace',
          }}
        >
          Select Verified Recipients
        </Typography>
        
        {Object.keys(verifiedRecipients).length === 0 ? (
          <Alert severity="info" sx={{ bgcolor: 'rgba(0, 255, 0, 0.1)' }}>
            No verified recipients found. Verify users first to share files with them.
          </Alert>
        ) : (
          <>
            <Box sx={{ mb: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Typography
                variant="body2"
                sx={{ color: 'rgba(0, 255, 0, 0.7)' }}
              >
                {selectedRecipients.length} recipient{selectedRecipients.length !== 1 ? 's' : ''} selected
              </Typography>
              {selectedRecipients.length > 0 && (
                <Button
                  size="small"
                  onClick={() => onRecipientsChange([])}
                  sx={{ color: 'rgba(255, 0, 0, 0.7)' }}
                >
                  Clear All
                </Button>
              )}
            </Box>
            <List sx={{ 
              maxHeight: 300, 
              overflowY: 'auto',
              border: '1px solid rgba(0, 255, 0, 0.2)',
              borderRadius: 1,
            }}>
              {Object.entries(verifiedRecipients).map(([username, bundle]) => (
                <ListItem
                  key={username}
                  button
                  onClick={() => {
                    onRecipientsChange(
                      selectedRecipients.includes(username)
                        ? selectedRecipients.filter(u => u !== username)
                        : [...selectedRecipients, username]
                    );
                  }}
                  selected={selectedRecipients.includes(username)}
                  sx={{
                    borderBottom: '1px solid rgba(0, 255, 0, 0.1)',
                    '&:hover': {
                      backgroundColor: 'rgba(0, 255, 0, 0.05)',
                    },
                    '&.Mui-selected': {
                      backgroundColor: 'rgba(0, 255, 0, 0.1)',
                      '&:hover': {
                        backgroundColor: 'rgba(0, 255, 0, 0.15)',
                      },
                    },
                  }}
                >
                  <ListItemIcon>
                    <VerifiedUserIcon sx={{ color: '#00ff00' }} />
                  </ListItemIcon>
                  <ListItemText
                    primary={username}
                    primaryTypographyProps={{
                      sx: { color: '#00ffff', fontWeight: 'bold' },
                    }}
                    secondary={`Verified on ${new Date(bundle.lastVerified).toLocaleDateString()}`}
                    secondaryTypographyProps={{
                      sx: { color: 'rgba(0, 255, 0, 0.7)' },
                    }}
                  />
                  <Checkbox
                    edge="end"
                    checked={selectedRecipients.includes(username)}
                    sx={{
                      color: 'rgba(0, 255, 0, 0.3)',
                      '&.Mui-checked': {
                        color: '#00ff00',
                      },
                    }}
                  />
                </ListItem>
              ))}
            </List>
          </>
        )}
      </DialogContent>
      <DialogActions sx={{ borderTop: '1px solid rgba(0, 255, 0, 0.2)', p: 2 }}>
        <Button 
          onClick={onClose}
          sx={{ color: 'rgba(0, 255, 0, 0.7)' }}
        >
          Cancel
        </Button>
        <CyberButton
          onClick={onShare}
          size="small"
          sx={{ minWidth: 100, fontSize: '0.95rem', height: 36, px: 2.5, py: 1 }}
          disabled={selectedRecipients.length === 0}
        >
          Share
        </CyberButton>
      </DialogActions>
    </Dialog>
  );
};