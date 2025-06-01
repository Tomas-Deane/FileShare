import React from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Box,
  Typography,
  LinearProgress,
  Alert,
} from '@mui/material';
import { Upload as UploadIcon } from '@mui/icons-material';
import CyberButton from '../../../CyberButton';


interface UploadDialogProps {
  open: boolean;
  onClose: () => void;
  loading: boolean;
  error: string | null;
  onFileUpload: (file: File) => Promise<void>;
  onDragEnter: (e: React.DragEvent) => void;
  onDragLeave: (e: React.DragEvent) => void;
  onDragOver: (e: React.DragEvent) => void;
  onDrop: (e: React.DragEvent) => void;
  dragActive: boolean;
}

export const UploadDialog: React.FC<UploadDialogProps> = ({
  open,
  onClose,
  loading,
  error,
  onFileUpload,
  onDragEnter,
  onDragLeave,
  onDragOver,
  onDrop,
  dragActive,
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
        Upload File
      </DialogTitle>
      <DialogContent sx={{ mt: 2, p: 0 }}>
        <Box
          onDragEnter={onDragEnter}
          onDragLeave={onDragLeave}
          onDragOver={onDragOver}
          onDrop={onDrop}
          sx={{
            width: 320,
            height: 200,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            border: '2px dashed rgba(0, 255, 0, 0.3)',
            borderRadius: 2,
            textAlign: 'center',
            cursor: loading ? 'default' : 'pointer',
            backgroundColor: dragActive ? 'rgba(0, 255, 0, 0.1)' : 'transparent',
            transition: 'background 0.2s',
            mx: 'auto',
            my: 2,
            '&:hover': {
              border: loading ? '2px dashed rgba(0, 255, 0, 0.3)' : '2px dashed rgba(0, 255, 0, 0.5)',
              backgroundColor: loading ? 'transparent' : 'rgba(0, 255, 0, 0.05)',
            },
            opacity: loading ? 0.7 : 1,
          }}
          component="label"
        >
          <input
            type="file"
            hidden
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) {
                onFileUpload(file);
              }
            }}
            disabled={loading}
          />
          <UploadIcon sx={{ fontSize: 48, color: '#00ff00', mb: 2 }} />
          <Typography sx={{ color: '#00ffff', mb: 1 }}>
            {loading ? 'Uploading...' : 'Drag and drop your file here'}
          </Typography>
          <Typography sx={{ color: 'rgba(0, 255, 0, 0.7)', fontSize: '0.875rem' }}>
            {loading ? 'Please wait...' : 'or click to browse'}
          </Typography>
        </Box>
        {loading && (
          <Box sx={{ width: '100%', px: 2, pb: 2 }}>
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
              Encrypting and uploading file...
            </Typography>
          </Box>
        )}
        {error && (
          <Alert severity="error" sx={{ mt: 2, bgcolor: 'rgba(255, 0, 0, 0.1)' }}>
            {error}
          </Alert>
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
      </DialogActions>
    </Dialog>
  );
};