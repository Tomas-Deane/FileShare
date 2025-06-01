import React from 'react';
import {
    Folder as FolderIcon,
    Share as ShareIcon,
    Download as DownloadIcon,
    Delete as DeleteIcon,
    Visibility as VisibilityIcon,
    Refresh as RefreshIcon,
    Upload as UploadIcon,
  } from '@mui/icons-material';
import {
    Box,
    Typography,
    List,
    ListItem,
    ListItemIcon,
    ListItemText,
    IconButton,
    Tooltip,
    Alert,
} from '@mui/material';
import { DashboardCard } from './shared/DashboardCard';
import CyberButton from '../CyberButton';

interface FileData {
  id: number;
  name: string;
  type: string;
  size: string;
  date: Date;
}

interface SharedFileData {
  id: number;
  share_id: number;
  filename: string;
  shared_by: string;
  created_at: string;
}

interface FilesTabProps {
  files: FileData[];
  sharedFiles: SharedFileData[];
  loading: boolean;
  loadingSharedFiles: boolean;
  error: string | null;
  searchQuery: string;
  onUpload: () => void;
  onShare: (fileId: number) => void;
  onDownload: (fileId: number, isShared: boolean) => void;
  onDelete: (fileId: number) => void;
  onPreview: (fileId: number) => void;
  onRefreshSharedFiles: () => void;
}

export const FilesTab: React.FC<FilesTabProps> = ({
  files,
  sharedFiles,
  loading,
  loadingSharedFiles,
  error,
  searchQuery,
  onUpload,
  onShare,
  onDownload,
  onDelete,
  onPreview,
  onRefreshSharedFiles,
}) => {
  return (
    <>
      {/* My Files Card */}
      <DashboardCard sx={{ mb: 3 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 3 }}>
          <Typography
            variant="h6"
            sx={{
              color: '#00ffff',
              textShadow: '0 0 10px rgba(0, 255, 0, 0.5)',
            }}
          >
            My Files
          </Typography>
          <CyberButton
            startIcon={<UploadIcon />}
            onClick={onUpload}
            sx={{ width: 180, fontSize: '1rem', height: 48, px: 0 }}
          >
            Upload File
          </CyberButton>
        </Box>

        {loading ? (
          <Box sx={{ textAlign: 'center', py: 4 }}>
            <Typography sx={{ color: '#00ff00' }}>Loading files...</Typography>
          </Box>
        ) : error ? (
          <Alert severity="error" sx={{ bgcolor: 'rgba(255, 0, 0, 0.1)' }}>
            {error}
          </Alert>
        ) : files.length === 0 ? (
          <Box sx={{ textAlign: 'center', py: 4 }}>
            <Typography sx={{ color: '#00ff00' }}>No files found. Upload your first file!</Typography>
          </Box>
        ) : (
          <List>
            {files
              .filter(file => file.name.toLowerCase().includes(searchQuery.toLowerCase()))
              .map((file) => (
                <ListItem
                  key={file.id}
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
                    <FolderIcon sx={{ color: '#00ff00' }} />
                  </ListItemIcon>
                  <ListItemText
                    primary={file.name}
                    secondary={`${file.type.toUpperCase()} • ${file.size} • ${file.date.toLocaleDateString('en-GB')} ${file.date.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })}`}
                    primaryTypographyProps={{
                      sx: { color: '#00ffff', fontWeight: 'bold' },
                    }}
                    secondaryTypographyProps={{
                      sx: { color: 'rgba(0, 255, 0, 0.7)' },
                    }}
                  />
                  <Box sx={{ display: 'flex', gap: 1 }}>
                    <Tooltip title="Share">
                      <IconButton onClick={() => onShare(file.id)} sx={{ color: '#00ff00' }}>
                        <ShareIcon />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Download">
                      <IconButton onClick={() => onDownload(file.id, false)} sx={{ color: '#00ff00' }}>
                        <DownloadIcon />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Delete">
                      <IconButton onClick={() => onDelete(file.id)} sx={{ color: '#00ff00' }}>
                        <DeleteIcon />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Preview">
                      <IconButton onClick={() => onPreview(file.id)} sx={{ color: '#00ff00' }}>
                        <VisibilityIcon />
                      </IconButton>
                    </Tooltip>
                  </Box>
                </ListItem>
              ))}
          </List>
        )}
      </DashboardCard>

      {/* Shared Files Card */}
      <DashboardCard>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Typography
            variant="h6"
            sx={{
              color: '#00ffff',
              textShadow: '0 0 10px rgba(0, 255, 0, 0.5)',
            }}
          >
            Files Shared With You
          </Typography>
          <IconButton 
            onClick={onRefreshSharedFiles} 
            sx={{ color: '#00ff00' }}
            disabled={loadingSharedFiles}
          >
            <RefreshIcon />
          </IconButton>
        </Box>
        {loadingSharedFiles ? (
          <Box sx={{ textAlign: 'center', py: 4 }}>
            <Typography sx={{ color: '#00ff00' }}>Loading shared files...</Typography>
          </Box>
        ) : sharedFiles.length === 0 ? (
          <Box sx={{ textAlign: 'center', py: 4 }}>
            <Typography sx={{ color: '#00ff00' }}>No files have been shared with you yet.</Typography>
          </Box>
        ) : (
          <List>
            {sharedFiles
              .filter(file => file.filename.toLowerCase().includes(searchQuery.toLowerCase()))
              .map((file) => (
                <ListItem
                  key={file.id}
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
                    <FolderIcon sx={{ color: '#00ff00' }} />
                  </ListItemIcon>
                  <ListItemText
                    primary={file.filename}
                    secondary={`Shared by ${file.shared_by} • ${new Date(file.created_at).toLocaleDateString()}`}
                    primaryTypographyProps={{
                      sx: { color: '#00ffff', fontWeight: 'bold' },
                    }}
                    secondaryTypographyProps={{
                      sx: { color: 'rgba(0, 255, 0, 0.7)' },
                    }}
                  />
                  <Box sx={{ display: 'flex', gap: 1 }}>
                    <Tooltip title="Download">
                      <IconButton onClick={() => onDownload(file.id, true)} sx={{ color: '#00ff00' }}>
                        <DownloadIcon />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Preview">
                      <IconButton onClick={() => onPreview(file.id)} sx={{ color: '#00ff00' }}>
                        <VisibilityIcon />
                      </IconButton>
                    </Tooltip>
                  </Box>
                </ListItem>
              ))}
          </List>
        )}
      </DashboardCard>
    </>
  );
};