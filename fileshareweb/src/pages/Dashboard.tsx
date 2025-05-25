import React, { useState } from 'react';
import {
  Box, Container, Typography, Button, Paper, Grid, List, ListItem, ListItemText,
  ListItemIcon, IconButton, Dialog, DialogTitle, DialogContent, DialogActions,
  TextField, Tabs, Tab, Tooltip, Alert, Drawer, InputAdornment, Divider
} from '@mui/material';
import {
  Upload as UploadIcon, Share as ShareIcon, Delete as DeleteIcon, Download as DownloadIcon,
  Folder as FolderIcon, Person as PersonIcon, Lock as LockIcon, LockOpen as LockOpenIcon,
  Search as SearchIcon, VerifiedUser as VerifiedUserIcon, People as PeopleIcon,
  Home as HomeIcon, Storage as StorageIcon, Security as SecurityIcon, Settings as SettingsIcon,
  Edit as EditIcon
} from '@mui/icons-material';
import { styled } from '@mui/material/styles';
import { useNavigate } from 'react-router-dom';
import { CyberButton, MatrixBackground } from '../components';
import { QRCodeSVG } from 'qrcode.react';

// Styled components for cyberpunk look
const DashboardCard = styled(Paper)(({ theme }) => ({
  background: 'rgba(0, 0, 0, 0.8)',
  backdropFilter: 'blur(10px)',
  border: '1px solid rgba(0, 255, 0, 0.2)',
  borderRadius: 8,
  padding: theme.spacing(3),
  height: '100%',
  transition: 'all 0.3s ease',
  '&:hover': {
    border: '1px solid rgba(0, 255, 0, 0.4)',
    boxShadow: '0 0 20px rgba(0, 255, 0, 0.2)',
  },
}));

const StyledTabs = styled(Tabs)({
  borderBottom: '1px solid rgba(0, 255, 0, 0.2)',
  '& .MuiTabs-indicator': {
    backgroundColor: '#00ff00',
  },
});

const StyledTab = styled(Tab)({
  color: '#00ff00',
  '&.Mui-selected': {
    color: '#00ffff',
  },
  '&:hover': {
    color: '#00ffff',
  },
});

const NavDrawer = styled(Drawer)(({ theme }) => ({
  width: 240,
  flexShrink: 0,
  '& .MuiDrawer-paper': {
    width: 240,
    background: 'rgba(0, 0, 0, 0.9)',
    borderRight: '1px solid rgba(0, 255, 0, 0.2)',
    boxSizing: 'border-box',
  },
}));

const SearchField = styled(TextField)(({ theme }) => ({
  '& .MuiOutlinedInput-root': {
    color: '#00ff00',
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
}));

// Mock data for demonstration
const mockFiles = [
  { id: 1, name: 'document.pdf', type: 'pdf', size: '2.5 MB', shared: false },
  { id: 2, name: 'image.jpg', type: 'image', size: '1.8 MB', shared: true },
  { id: 3, name: 'code.zip', type: 'archive', size: '5.2 MB', shared: false },
];

const mockSharedFiles = [
  { id: 4, name: 'shared_doc.pdf', type: 'pdf', size: '3.1 MB', sharedBy: 'user1' },
  { id: 5, name: 'shared_image.jpg', type: 'image', size: '2.3 MB', sharedBy: 'user2' },
];

const mockUsers = [
  { id: 1, email: 'user1@example.com', verified: true },
  { id: 2, email: 'user2@example.com', verified: false },
  { id: 3, email: 'user3@example.com', verified: true },
];

// Update the ProfileData interface
interface ProfileData {
  username: string;
  email: string;
  storageUsed: string;
  storageLimit: string;
  lastLogin: string;
}

// Update the mockUserProfile
const mockUserProfile: ProfileData = {
  username: 'cyberpunk_user',
  email: 'user@example.com',
  storageUsed: '2.5 GB',
  storageLimit: '10 GB',
  lastLogin: '2024-03-20 15:30',
};

const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState('files');
  const [searchQuery, setSearchQuery] = useState('');
  const [userSearchQuery, setUserSearchQuery] = useState('');
  const [openUpload, setOpenUpload] = useState(false);
  const [openShare, setOpenShare] = useState(false);
  const [selectedFile, setSelectedFile] = useState<number | null>(null);
  const [shareEmail, setShareEmail] = useState('');
  const [openVerify, setOpenVerify] = useState(false);
  const [selectedUser, setSelectedUser] = useState<{ id: number; email: string } | null>(null);
  const [openProfileSettings, setOpenProfileSettings] = useState(false);
  const [profileData, setProfileData] = useState<ProfileData>(mockUserProfile);
  const [editMode, setEditMode] = useState(false);
  const [editedProfile, setEditedProfile] = useState<ProfileData>(mockUserProfile);
  const [verificationCode] = useState(() => {
    // Generate a random 60-digit integer
    return Array.from({ length: 60 }, () => Math.floor(Math.random() * 10)).join('');
  });

  // Filter files based on search query
  const filteredFiles = mockFiles.filter(file => 
    file.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  // Filter users based on search query
  const filteredUsers = mockUsers.filter(user =>
    user.email.toLowerCase().includes(userSearchQuery.toLowerCase())
  );

  const handleTabChange = (event: React.SyntheticEvent, newValue: string) => setActiveTab(newValue);
  const handleUpload = () => setOpenUpload(true);
  const handleShare = (fileId: number) => { setSelectedFile(fileId); setOpenShare(true); };
  const handleDelete = (fileId: number) => { /* TODO: Implement delete */ };
  const handleDownload = (fileId: number) => { /* TODO: Implement download */ };
  const handleRevoke = (fileId: number) => { /* TODO: Implement revoke */ };
  const handleVerifyClick = (user: { id: number; email: string }) => {
    setSelectedUser(user);
    setOpenVerify(true);
  };

  const handleProfileEdit = () => {
    setEditMode(true);
    setEditedProfile(profileData);
  };

  const handleProfileSave = () => {
    setProfileData(editedProfile);
    setEditMode(false);
    // TODO: Implement profile update logic
  };

  const handleProfileCancel = () => {
    setEditMode(false);
    setEditedProfile(profileData);
  };

  return (
    <>
      <MatrixBackground />
      <Box sx={{ display: 'flex' }}>
        {/* Left Navigation Drawer */}
        <NavDrawer variant="permanent">
          <Box sx={{ p: 2, display: 'flex', flexDirection: 'column', height: '100%' }}>
            <Typography
              variant="h6"
              sx={{
                color: '#00ff00',
                textShadow: '0 0 10px rgba(0, 255, 0, 0.5)',
                fontFamily: 'monospace',
                fontWeight: 'bold',
                mb: 2,
              }}
            >
              FileShare
            </Typography>
            <List sx={{ flexGrow: 1 }}>
              <ListItem component="div" onClick={() => setActiveTab('files')}>
                <ListItemIcon>
                  <StorageIcon sx={{ color: '#00ff00' }} />
                </ListItemIcon>
                <ListItemText 
                  primary="Files" 
                  sx={{ color: '#00ff00' }}
                />
              </ListItem>
              <ListItem component="div" onClick={() => setActiveTab('users')}>
                <ListItemIcon>
                  <PeopleIcon sx={{ color: '#00ff00' }} />
                </ListItemIcon>
                <ListItemText 
                  primary="Users" 
                  sx={{ color: '#00ff00' }}
                />
              </ListItem>
              <ListItem component="div" onClick={() => navigate('/login')}>
                <ListItemIcon>
                  <LockIcon sx={{ color: '#00ff00' }} />
                </ListItemIcon>
                <ListItemText 
                  primary="Logout" 
                  sx={{ color: '#00ff00' }}
                />
              </ListItem>
            </List>
            <Divider sx={{ borderColor: 'rgba(0, 255, 0, 0.2)' }} />
            <List>
              <ListItem component="div" onClick={() => setActiveTab('profile')}>
                <ListItemIcon>
                  <PersonIcon sx={{ color: '#00ff00' }} />
                </ListItemIcon>
                <ListItemText 
                  primary="Profile" 
                  sx={{ color: '#00ff00' }}
                />
              </ListItem>
            </List>
          </Box>
        </NavDrawer>

        {/* Main Content */}
        <Box component="main" sx={{ flexGrow: 1, p: 3 }}>
          <Container maxWidth="xl">
            {/* Header with Search */}
            <Box sx={{ mb: 4 }}>
              <SearchField
                fullWidth
                placeholder="Search files..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <SearchIcon sx={{ color: '#00ff00' }} />
                    </InputAdornment>
                  ),
                }}
              />
            </Box>

            {/* Content Area */}
            {activeTab === 'files' ? (
              <DashboardCard>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 3 }}>
                  <Typography
                    variant="h6"
                    sx={{
                      color: '#00ffff',
                      textShadow: '0 0 10px rgba(0, 255, 0, 0.5)',
                    }}
                  >
                    Your Files
                  </Typography>
                  <CyberButton
                    startIcon={<UploadIcon />}
                    onClick={() => setOpenUpload(true)}
                    sx={{ width: 180, fontSize: '1rem', height: 48, px: 0 }}
                  >
                    Upload File
                  </CyberButton>
                </Box>
                <List>
                  {filteredFiles.map((file) => (
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
                        secondary={`${file.type.toUpperCase()} • ${file.size}`}
                        primaryTypographyProps={{
                          sx: { color: '#00ffff', fontWeight: 'bold' },
                        }}
                        secondaryTypographyProps={{
                          sx: { color: 'rgba(0, 255, 0, 0.7)' },
                        }}
                      />
                      <Box sx={{ display: 'flex', gap: 1 }}>
                        <Tooltip title="Share">
                          <IconButton onClick={() => handleShare(file.id)} sx={{ color: '#00ff00' }}>
                            <ShareIcon />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Download">
                          <IconButton onClick={() => handleDownload(file.id)} sx={{ color: '#00ff00' }}>
                            <DownloadIcon />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Delete">
                          <IconButton onClick={() => handleDelete(file.id)} sx={{ color: '#00ff00' }}>
                            <DeleteIcon />
                          </IconButton>
                        </Tooltip>
                      </Box>
                    </ListItem>
                  ))}
                </List>
              </DashboardCard>
            ) : activeTab === 'users' ? (
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
                    User Verification
                  </Typography>
                  <SearchField
                    fullWidth
                    placeholder="Search users..."
                    value={userSearchQuery}
                    onChange={(e) => setUserSearchQuery(e.target.value)}
                    InputProps={{
                      startAdornment: (
                        <InputAdornment position="start">
                          <SearchIcon sx={{ color: '#00ff00' }} />
                        </InputAdornment>
                      ),
                    }}
                  />
                </Box>
                <List>
                  {filteredUsers.map((user) => (
                    <ListItem
                      key={user.id}
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
                        {user.verified ? (
                          <VerifiedUserIcon sx={{ color: '#00ff00' }} />
                        ) : (
                          <PersonIcon sx={{ color: 'rgba(0, 255, 0, 0.5)' }} />
                        )}
                      </ListItemIcon>
                      <ListItemText
                        primary={user.email}
                        secondary={user.verified ? 'Verified' : 'Not Verified'}
                        primaryTypographyProps={{
                          sx: { color: '#00ffff', fontWeight: 'bold' },
                        }}
                        secondaryTypographyProps={{
                          sx: { color: user.verified ? '#00ff00' : 'rgba(0, 255, 0, 0.5)' },
                        }}
                      />
                      {!user.verified && (
                        <CyberButton
                          size="small"
                          startIcon={<VerifiedUserIcon />}
                          onClick={() => handleVerifyClick(user)}
                          sx={{ minWidth: 100, fontSize: '0.95rem', height: 36, px: 2.5, py: 1 }}
                        >
                          Verify
                        </CyberButton>
                      )}
                    </ListItem>
                  ))}
                </List>
              </DashboardCard>
            ) : (
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
                    onClick={() => setOpenProfileSettings(true)}
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
            )}
          </Container>
        </Box>
      </Box>

      {/* Upload Dialog */}
      <Dialog
        open={openUpload}
        onClose={() => setOpenUpload(false)}
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
        <DialogContent sx={{ mt: 2 }}>
          <Box
            sx={{
              border: '2px dashed rgba(0, 255, 0, 0.3)',
              borderRadius: 2,
              p: 3,
              textAlign: 'center',
              cursor: 'pointer',
              '&:hover': {
                border: '2px dashed rgba(0, 255, 0, 0.5)',
                backgroundColor: 'rgba(0, 255, 0, 0.05)',
              },
            }}
          >
            <UploadIcon sx={{ fontSize: 48, color: '#00ff00', mb: 2 }} />
            <Typography sx={{ color: '#00ffff', mb: 1 }}>
              Drag and drop your file here
            </Typography>
            <Typography sx={{ color: 'rgba(0, 255, 0, 0.7)', fontSize: '0.875rem' }}>
              or click to browse
            </Typography>
          </Box>
        </DialogContent>
        <DialogActions sx={{ borderTop: '1px solid rgba(0, 255, 0, 0.2)', p: 2 }}>
          <Button onClick={() => setOpenUpload(false)} sx={{ color: 'rgba(0, 255, 0, 0.7)' }}>
            Cancel
          </Button>
          <CyberButton
            onClick={() => setOpenUpload(false)}
            size="small"
            sx={{ minWidth: 100, fontSize: '0.95rem', height: 36, px: 2.5, py: 1 }}
          >
            Upload
          </CyberButton>
        </DialogActions>
      </Dialog>

      {/* Share Dialog */}
      <Dialog
        open={openShare}
        onClose={() => setOpenShare(false)}
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
          <TextField
            fullWidth
            label="User Email"
            variant="outlined"
            value={shareEmail}
            onChange={(e) => setShareEmail(e.target.value)}
            sx={{
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
        </DialogContent>
        <DialogActions sx={{ borderTop: '1px solid rgba(0, 255, 0, 0.2)', p: 2 }}>
          <Button onClick={() => setOpenShare(false)} sx={{ color: 'rgba(0, 255, 0, 0.7)' }}>
            Cancel
          </Button>
          <CyberButton
            onClick={() => setOpenShare(false)}
            size="small"
            sx={{ minWidth: 100, fontSize: '0.95rem', height: 36, px: 2.5, py: 1 }}
          >
            Share
          </CyberButton>
        </DialogActions>
      </Dialog>

      {/* Verification Dialog */}
      <Dialog
        open={openVerify}
        onClose={() => setOpenVerify(false)}
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
            {selectedUser?.email}
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
            onClick={() => setOpenVerify(false)}
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
            onClick={() => {
              // TODO: Implement verification logic
              setOpenVerify(false);
            }}
            size="small"
            sx={{ minWidth: 100, fontSize: '0.95rem', height: 36, px: 2.5, py: 1 }}
          >
            Verify
          </CyberButton>
        </DialogActions>
      </Dialog>

      {/* Profile Settings Dialog */}
      <Dialog
        open={openProfileSettings}
        onClose={() => setOpenProfileSettings(false)}
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
              onChange={(e) => setEditedProfile({ ...editedProfile, username: e.target.value })}
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
              onChange={(e) => setEditedProfile({ ...editedProfile, email: e.target.value })}
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
            onClick={() => setOpenProfileSettings(false)}
            sx={{ color: 'rgba(0, 255, 0, 0.7)' }}
          >
            Cancel
          </Button>
          {editMode ? (
            <>
              <Button
                onClick={handleProfileCancel}
                sx={{ color: 'rgba(255, 0, 0, 0.7)' }}
              >
                Cancel Edit
              </Button>
              <CyberButton onClick={handleProfileSave}>
                Save Changes
              </CyberButton>
            </>
          ) : (
            <CyberButton onClick={handleProfileEdit}>
              Edit Profile
            </CyberButton>
          )}
        </DialogActions>
      </Dialog>
    </>
  );
};

export default Dashboard;