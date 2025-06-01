import React from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Typography,
  Box,
  LinearProgress,
} from '@mui/material';
import CyberButton from '../../../CyberButton';
interface DeleteDialogProps {
  open: boolean;
  onClose: () => void;
  loading: boolean;
  onDelete: () => void;
}

export const DeleteDialog: React.FC<DeleteDialogProps> = ({
  open,
  onClose,
  loading,
  onDelete,
}) => {
  return (
    <Dialog
      open={open}
      onClose={() => {
        if (!loading) {
          onClose();
        }
      }}
      PaperProps={{
        sx: {
          background: 'rgba(0, 0, 0, 0.9)',
          border: '1px solid rgba(0, 255, 0, 0.2)',
          color: '#00ff00',
        },
      }}
    >
      <DialogTitle sx={{ color: '#00ffff', borderBottom: '1px solid rgba(0, 255, 0, 0.2)' }}>
        Confirm Delete
      </DialogTitle>
      <DialogContent sx={{ mt: 2 }}>
        <Typography sx={{ color: '#00ff00', mb: 2 }}>
          Are you sure you want to delete this file? This action cannot be undone.
        </Typography>
        {loading && (
          <Box sx={{ width: '100%', mt: 2 }}>
            <LinearProgress 
              sx={{
                backgroundColor: 'rgba(0, 255, 0, 0.1)',
                '& .MuiLinearProgress-bar': {
                  backgroundColor: '#00ff00',
                  boxShadow: '0 0 10px rgba(0, 255, 0, 0.5)',
                },
              }}
            />
            <Typography 
              variant="body2" 
              sx={{ 
                color: 'rgba(0, 255, 0, 0.7)', 
                mt: 1,
                textAlign: 'center',
                fontFamily: 'monospace'
              }}
            >
              Deleting file...
            </Typography>
          </Box>
        )}
      </DialogContent>
      <DialogActions sx={{ borderTop: '1px solid rgba(0, 255, 0, 0.2)', p: 2 }}>
        <Button
          onClick={onClose}
          sx={{ color: 'rgba(0, 255, 0, 0.7)' }}
          disabled={loading}
        >
          Cancel
        </Button>
        <CyberButton
          onClick={onDelete}
          size="small"
          sx={{ 
            minWidth: 100, 
            fontSize: '0.95rem', 
            height: 36, 
            px: 2.5, 
            py: 1,
            backgroundColor: 'rgba(255, 0, 0, 0.2)',
            '&:hover': {
              backgroundColor: 'rgba(255, 0, 0, 0.3)',
            },
          }}
          disabled={loading}
        >
          Delete
        </CyberButton>
      </DialogActions>
    </Dialog>
  );
};