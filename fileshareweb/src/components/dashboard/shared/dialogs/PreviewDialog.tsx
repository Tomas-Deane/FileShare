import React from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Typography,
  Box,
  Alert,
} from '@mui/material';

interface PreviewDialogProps {
  open: boolean;
  onClose: () => void;
  previewContent: string | null;
  previewImageUrl: string | null;
  previewError: string | null;
  previewLoading: boolean;
}

export const PreviewDialog: React.FC<PreviewDialogProps> = ({
  open,
  onClose,
  previewContent,
  previewImageUrl,
  previewError,
  previewLoading,
}) => {
  return (
    <Dialog
      open={open}
      onClose={onClose}
      PaperProps={{
        sx: {
          background: 'rgba(0, 0, 0, 0.95)',
          border: '1px solid rgba(0, 255, 0, 0.2)',
          color: '#00ff00',
          minWidth: '600px',
          maxWidth: '80vw',
        },
      }}
      maxWidth="md"
      fullWidth
    >
      <DialogTitle sx={{ color: '#00ffff', borderBottom: '1px solid rgba(0, 255, 0, 0.2)' }}>
        File Preview
      </DialogTitle>
      <DialogContent sx={{ mt: 2 }}>
        {previewLoading ? (
          <Typography sx={{ color: '#00ff00' }}>Loading preview...</Typography>
        ) : previewError ? (
          <Alert severity="error" sx={{ bgcolor: 'rgba(255, 0, 0, 0.1)' }}>{previewError}</Alert>
        ) : previewImageUrl ? (
          <Box sx={{ textAlign: 'center' }}>
            <img src={previewImageUrl} alt="Preview" style={{ maxWidth: '100%', maxHeight: 400 }} />
          </Box>
        ) : previewContent ? (
          <Box sx={{
            bgcolor: 'rgba(0,255,0,0.05)',
            border: '1px solid rgba(0,255,0,0.2)',
            borderRadius: 1,
            p: 2,
            maxHeight: '60vh',
            overflowY: 'auto',
            fontFamily: 'monospace',
            color: '#00ff00',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-all',
          }}>
            {previewContent}
          </Box>
        ) : null}
      </DialogContent>
      <DialogActions sx={{ borderTop: '1px solid rgba(0, 255, 0, 0.2)', p: 2 }}>
        <Button onClick={onClose} sx={{ color: 'rgba(0, 255, 0, 0.7)' }}>
          Close
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export {};