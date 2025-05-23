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
  Home as HomeIcon, Storage as StorageIcon, Security as SecurityIcon
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
  { id: 4, name: 'presentation.pptx', type: 'ppt', size: '4.1 MB', shared: false },
  { id: 5, name: 'notes.txt', type: 'text', size: '0.8 MB', shared: false },
  { id: 6, name: 'spreadsheet.xlsx', type: 'excel', size: '3.7 MB', shared: false },
];

const mockSharedFiles = [
  { id: 4, name: 'shared_doc.pdf', type: 'pdf', size: '3.1 MB', sharedBy: 'user1' },
  { id: 5, name: 'shared_image.jpg', type: 'image', size: '2.3 MB', sharedBy: 'user2' },
  { id: 6, name: 'project_plan.docx', type: 'doc', size: '1.9 MB', sharedBy: 'user3' },
  { id: 7, name: 'budget.xlsx', type: 'excel', size: '2.8 MB', sharedBy: 'user4' },
  { id: 8, name: 'meeting_minutes.txt', type: 'text', size: '0.6 MB', sharedBy: 'user5' },
];

const mockUsers = [
  { id: 1, email: 'user1@example.com', verified: true },
  { id: 2, email: 'user2@example.com', verified: true },
  { id: 3, email: 'user3@example.com', verified: true },
  { id: 4, email: 'user4@example.com', verified: true },
  { id: 5, email: 'user5@example.com', verified: true },
  { id: 6, email: 'user6@example.com', verified: true },
];

const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<'home'|'files'|'users'>('home');
  const [searchQuery, setSearchQuery] = useState('');
  const [userSearchQuery, setUserSearchQuery] = useState('');
  const [openUpload, setOpenUpload] = useState(false);
  const [openShare, setOpenShare] = useState(false);
  const [selectedFile, setSelectedFile] = useState<number | null>(null);
  const [shareEmail, setShareEmail] = useState('');
  const [openVerify, setOpenVerify] = useState(false);
  const [selectedUser, setSelectedUser] = useState<{ id: number; email: string } | null>(null);
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

  const handleUpload = () => setOpenUpload(true);
  const handleShare = (fileId: number) => { setSelectedFile(fileId); setOpenShare(true); };
  const handleDelete = (fileId: number) => { /* TODO: Implement delete */ };
  const handleDownload = (fileId: number) => { /* TODO: Implement download */ };
  const handleRevoke = (fileId: number) => { /* TODO: Implement revoke */ };
  const handleVerifyClick = (user: { id: number; email: string }) => {
    setSelectedUser(user);
    setOpenVerify(true);
  };

  return (
    <>
      <MatrixBackground />
      <Box sx={{ display: 'flex' }}>
        {/* Left Navigation Drawer */}
        <NavDrawer variant="permanent">
          <Box sx={{ p: 2 }}>
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
            <List>
              <ListItem
                button
                selected={activeTab === 'home'}
                onClick={() => setActiveTab('home')}
              >
                <ListItemIcon>
                  <HomeIcon sx={{ color: '#00ff00' }} />
                </ListItemIcon>
                <ListItemText primary="Home" sx={{ color: '#00ff00' }} />
              </ListItem>
              <Divider sx={{ borderColor: 'rgba(0,255,0,0.2)', my: 1 }} />

              <ListItem
                button
                selected={activeTab === 'files'}
                onClick={() => setActiveTab('files')}
              >
                <ListItemIcon>
                  <StorageIcon sx={{ color: '#00ff00' }} />
                </ListItemIcon>
                <ListItemText primary="Files" sx={{ color: '#00ff00' }} />
              </ListItem>

              <ListItem
                button
                selected={activeTab === 'users'}
                onClick={() => setActiveTab('users')}
              >
                <ListItemIcon>
                  <PeopleIcon sx={{ color: '#00ff00' }} />
                </ListItemIcon>
                <ListItemText primary="Users" sx={{ color: '#00ff00' }} />
              </ListItem>

              <ListItem button onClick={() => navigate('/login')}>
                <ListItemIcon>
                  <LockIcon sx={{ color: '#00ff00' }} />
                </ListItemIcon>
                <ListItemText primary="Logout" sx={{ color: '#00ff00' }} />
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
            {activeTab === 'home' ? (
              <>
                {/* Verified Users Section */}
                <DashboardCard sx={{ mb: 3 }}>
                  <Typography variant="h6" sx={{ color: '#00ffff', mb: 2 }}>
                    Verified Users
                  </Typography>
                  <Grid container spacing={2}>
                    {mockUsers
                      .filter((u) => u.verified)
                      .slice(0, 6)
                      .map((u) => (
                        <Grid item xs={4} sm={2} key={u.id}>
                          <Paper
                            sx={{
                              p: 2,
                              textAlign: 'center',
                              background: 'rgba(0,0,0,0.6)',
                            }}
                          >
                            <VerifiedUserIcon sx={{ fontSize: 32, color: '#00ff00' }} />
                            <Typography
                              sx={{ mt: 1, color: '#00ffff', fontSize: '0.875rem' }}
                            >
                              {u.email}
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
                    {mockSharedFiles.slice(0, 10).map((f) => (
                      <ListItem
                        key={f.id}
                        sx={{
                          mb: 1,
                          border: '1px solid rgba(0,255,0,0.2)',
                          borderRadius: 1,
                        }}
                      >
                        <ListItemIcon>
                          <FolderIcon sx={{ color: '#00ff00' }} />
                        </ListItemIcon>
                        <ListItemText
                          primary={f.name}
                          secondary={`${f.type.toUpperCase()} • ${f.size} • from ${f.sharedBy}`}
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
            ) : activeTab === 'files' ? (
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
            ) : (
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
    </>
  );
};

export default Dashboard;