import React from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Typography,
  Box,
} from '@mui/material';
import { QRCodeSVG } from 'qrcode.react';
import CyberButton from '../../../CyberButton';

interface VerifyDialogProps {
  open: boolean;
  onClose: () => void;
  selectedUser: { id: number; username: string } | null;
  verificationCode: string;
  onVerify: () => void;
}

export const VerifyDialog: React.FC<VerifyDialogProps> = ({
  open,
  onClose,
  selectedUser,
  verificationCode,
  onVerify,
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
        Verify User
      </DialogTitle>
      <DialogContent sx={{ mt: 2, textAlign: 'center' }}>
        <Typography
          variant="subtitle1"
          sx={{
            color: '#00ffff',
            mb: 2,
            fontFamily: 'monospace',
          }}
        >
          {selectedUser?.username}
        </Typography>
        
        {/* QR Code */}
        <Box
          sx={{
            p: 2,
            mb: 2,
            display: 'flex',
            justifyContent: 'center',
            backgroundColor: 'rgba(0, 255, 0, 0.05)',
            borderRadius: 1,
          }}
        >
          <QRCodeSVG
            value={verificationCode}
            size={200}
            level="H"
            includeMargin={true}
            bgColor="transparent"
            fgColor="#00ff00"
          />
        </Box>

        {/* Verification Code */}
        <Typography
          variant="body1"
          sx={{
            color: '#00ff00',
            fontFamily: 'monospace',
            letterSpacing: '0.1em',
            mb: 3,
            wordBreak: 'break-all',
          }}
        >
          {verificationCode}
        </Typography>
      </DialogContent>
      <DialogActions sx={{ borderTop: '1px solid rgba(0, 255, 0, 0.2)', p: 2, justifyContent: 'center', gap: 2 }}>
        <Button
          onClick={onClose}
          sx={{
            color: 'rgba(255, 0, 0, 0.7)',
            borderColor: 'rgba(255, 0, 0, 0.3)',
            '&:hover': {
              borderColor: 'rgba(255, 0, 0, 0.5)',
              backgroundColor: 'rgba(255, 0, 0, 0.1)',
            },
          }}
          variant="outlined"
        >
          Don't Trust
        </Button>
        <CyberButton
          onClick={onVerify}
          size="small"
          sx={{ minWidth: 100, fontSize: '0.95rem', height: 36, px: 2.5, py: 1 }}
        >
          Verify
        </CyberButton>
      </DialogActions>
    </Dialog>
  );
};