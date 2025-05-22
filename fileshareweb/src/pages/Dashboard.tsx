import React, { useState } from 'react';
import {
  Box, Container, Typography, Button, Paper, Grid, List, ListItem, ListItemText,
  ListItemIcon, IconButton, Dialog, DialogTitle, DialogContent, DialogActions,
  TextField, Tabs, Tab, Tooltip, Alert, Drawer, InputAdornment, Divider, Avatar,
  Select, MenuItem, FormControl, InputLabel, Card, CardContent
} from '@mui/material';
import {
  Upload as UploadIcon, Share as ShareIcon, Delete as DeleteIcon, Download as DownloadIcon,
  Folder as FolderIcon, Person as PersonIcon, Lock as LockIcon, LockOpen as LockOpenIcon,
  Search as SearchIcon, VerifiedUser as VerifiedUserIcon, People as PeopleIcon,
  Home as HomeIcon, Storage as StorageIcon, Security as SecurityIcon, Settings as SettingsIcon,
  Edit as EditIcon, PhotoCamera as PhotoCameraIcon,
  PictureAsPdf as PdfIcon,
  Image as ImageIcon,
  Description as TextIcon,
  Code as CodeIcon,
  Movie as VideoIcon,
  Audiotrack as AudioIcon,
  Archive as ArchiveIcon,
  InsertDriveFile as DefaultFileIcon,
  Sort as SortIcon,
  AccessTime as AccessTimeIcon
} from '@mui/icons-material';
import { styled } from '@mui/material/styles';
import { useNavigate } from 'react-router-dom';
import MatrixBackground from '../components/MatrixBackground.tsx';
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

const CyberButton = styled(Button)(({ theme }) => ({
  background: 'linear-gradient(45deg, #00ff00 30%, #00ffff 90%)',
  border: 0,
  borderRadius: 3,
  boxShadow: '0 3px 5px 2px rgba(0, 255, 0, .3)',
  color: '#000',
  height: 48,
  padding: '0 24px',
  fontSize: '1rem',
  textTransform: 'uppercase',
  letterSpacing: '0.1em',
  transition: 'all 0.3s ease',
  position: 'relative',
  overflow: 'hidden',
  '&:hover': {
    background: 'linear-gradient(45deg, #00ffff 30%, #00ff00 90%)',
    transform: 'scale(1.05)',
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

// Add this after the mock data and before the Dashboard component
const getFileIcon = (fileName: string) => {
  const extension = fileName.split('.').pop()?.toLowerCase();
  
  const iconMap: { [key: string]: React.ReactElement } = {
    // Documents
    'pdf': <PdfIcon sx={{ color: '#ff0000' }} />,
    'doc': <TextIcon sx={{ color: '#2196f3' }} />,
    'docx': <TextIcon sx={{ color: '#2196f3' }} />,
    'txt': <TextIcon sx={{ color: '#757575' }} />,
    'rtf': <TextIcon sx={{ color: '#757575' }} />,
    
    // Images
    'jpg': <ImageIcon sx={{ color: '#4caf50' }} />,
    'jpeg': <ImageIcon sx={{ color: '#4caf50' }} />,
    'png': <ImageIcon sx={{ color: '#4caf50' }} />,
    'gif': <ImageIcon sx={{ color: '#4caf50' }} />,
    'bmp': <ImageIcon sx={{ color: '#4caf50' }} />,
    'svg': <ImageIcon sx={{ color: '#4caf50' }} />,
    
    // Code
    'js': <CodeIcon sx={{ color: '#f7df1e' }} />,
    'jsx': <CodeIcon sx={{ color: '#61dafb' }} />,
    'ts': <CodeIcon sx={{ color: '#007acc' }} />,
    'tsx': <CodeIcon sx={{ color: '#007acc' }} />,
    'html': <CodeIcon sx={{ color: '#e34c26' }} />,
    'css': <CodeIcon sx={{ color: '#264de4' }} />,
    'py': <CodeIcon sx={{ color: '#3776ab' }} />,
    'java': <CodeIcon sx={{ color: '#007396' }} />,
    'cpp': <CodeIcon sx={{ color: '#00599c' }} />,
    'c': <CodeIcon sx={{ color: '#00599c' }} />,
    
    // Media
    'mp4': <VideoIcon sx={{ color: '#ff4081' }} />,
    'avi': <VideoIcon sx={{ color: '#ff4081' }} />,
    'mov': <VideoIcon sx={{ color: '#ff4081' }} />,
    'mp3': <AudioIcon sx={{ color: '#9c27b0' }} />,
    'wav': <AudioIcon sx={{ color: '#9c27b0' }} />,
    'ogg': <AudioIcon sx={{ color: '#9c27b0' }} />,
    
    // Archives
    'zip': <ArchiveIcon sx={{ color: '#ff9800' }} />,
    'rar': <ArchiveIcon sx={{ color: '#ff9800' }} />,
    '7z': <ArchiveIcon sx={{ color: '#ff9800' }} />,
    'tar': <ArchiveIcon sx={{ color: '#ff9800' }} />,
    'gz': <ArchiveIcon sx={{ color: '#ff9800' }} />,
  };

  return iconMap[extension || ''] || <DefaultFileIcon sx={{ color: '#757575' }} />;
};

// Add these types after the existing interfaces
type SortOption = 'name' | 'date' | 'size' | 'type';
type SortDirection = 'asc' | 'desc';

// Add this after the existing interfaces
interface RecentFile {
  id: number;
  name: string;
  type: string;
  size: string;
  date: string;
  lastModified: string;
  shared: boolean;
}

// Update mock files to include lastModified
const mockFiles: RecentFile[] = [
  { id: 1, name: 'document.pdf', type: 'pdf', size: '2.5 MB', shared: false, date: '2024-03-20T10:30:00', lastModified: '2024-03-20T10:30:00' },
  { id: 2, name: 'image.jpg', type: 'image', size: '1.8 MB', shared: true, date: '2024-03-19T15:45:00', lastModified: '2024-03-20T09:15:00' },
  { id: 3, name: 'code.zip', type: 'archive', size: '5.2 MB', shared: false, date: '2024-03-21T09:15:00', lastModified: '2024-03-21T08:30:00' },
  { id: 4, name: 'script.js', type: 'code', size: '0.5 MB', shared: false, date: '2024-03-18T14:20:00', lastModified: '2024-03-21T11:45:00' },
  { id: 5, name: 'video.mp4', type: 'video', size: '15.7 MB', shared: true, date: '2024-03-22T11:00:00', lastModified: '2024-03-22T10:30:00' },
  { id: 6, name: 'music.mp3', type: 'audio', size: '3.2 MB', shared: false, date: '2024-03-17T16:30:00', lastModified: '2024-03-22T09:15:00' },
  { id: 7, name: 'styles.css', type: 'code', size: '0.3 MB', shared: false, date: '2024-03-16T13:45:00', lastModified: '2024-03-22T08:45:00' },
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

// Add these interfaces after the existing interfaces
interface ProfileData {
  username: string;
  email: string;
  avatar: string | null;
  storageUsed: string;
  storageLimit: string;
  lastLogin: string;
}

// Update the mockUserProfile to use the interface
const mockUserProfile: ProfileData = {
  username: 'cyberpunk_user',
  email: 'user@example.com',
  avatar: null,
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
  const [avatarPreview, setAvatarPreview] = useState<string | null>(null);
  const [avatarError, setAvatarError] = useState<string>('');
  const [sortBy, setSortBy] = useState<SortOption>('name');
  const [sortDirection, setSortDirection] = useState<SortDirection>('asc');

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

  const handleAvatarChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    // Validate file type
    if (!file.type.startsWith('image/')) {
      setAvatarError('Please select an image file');
      return;
    }

    // Validate file size (max 5MB)
    if (file.size > 5 * 1024 * 1024) {
      setAvatarError('Image size should be less than 5MB');
      return;
    }

    setAvatarError('');
    const reader = new FileReader();
    reader.onloadend = () => {
      setAvatarPreview(reader.result as string);
      setEditedProfile(prev => ({
        ...prev,
        avatar: reader.result as string
      }));
    };
    reader.readAsDataURL(file);
  };

  const handleProfileSave = () => {
    setProfileData(editedProfile);
    setEditMode(false);
    setAvatarPreview(null);
    // TODO: Implement profile update logic
  };

  const handleProfileCancel = () => {
    setEditMode(false);
    setEditedProfile(profileData);
    setAvatarPreview(null);
    setAvatarError('');
  };

  const handleSortChange = (event: React.ChangeEvent<{ value: unknown }>) => {
    const newSortBy = event.target.value as SortOption;
    if (newSortBy === sortBy) {
      // Toggle direction if clicking the same sort option
      setSortDirection(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(newSortBy);
      setSortDirection('asc');
    }
  };

  const getSizeInBytes = (sizeStr: string): number => {
    const [size, unit] = sizeStr.split(' ');
    const numSize = parseFloat(size);
    switch (unit) {
      case 'KB': return numSize * 1024;
      case 'MB': return numSize * 1024 * 1024;
      case 'GB': return numSize * 1024 * 1024 * 1024;
      default: return numSize;
    }
  };

  const sortedAndFilteredFiles = React.useMemo(() => {
    let sorted = [...filteredFiles];
    
    switch (sortBy) {
      case 'name':
        sorted.sort((a, b) => {
          const comparison = a.name.localeCompare(b.name);
          return sortDirection === 'asc' ? comparison : -comparison;
        });
        break;
      case 'date':
        sorted.sort((a, b) => {
          const comparison = new Date(a.date).getTime() - new Date(b.date).getTime();
          return sortDirection === 'asc' ? comparison : -comparison;
        });
        break;
      case 'size':
        sorted.sort((a, b) => {
          const comparison = getSizeInBytes(a.size) - getSizeInBytes(b.size);
          return sortDirection === 'asc' ? comparison : -comparison;
        });
        break;
      case 'type':
        sorted.sort((a, b) => {
          const comparison = a.type.localeCompare(b.type);
          return sortDirection === 'asc' ? comparison : -comparison;
        });
        break;
    }
    
    return sorted;
  }, [filteredFiles, sortBy, sortDirection]);

  // Add this function to get recent files
  const getRecentFiles = React.useMemo(() => {
    return [...mockFiles]
      .sort((a, b) => new Date(b.lastModified).getTime() - new Date(a.lastModified).getTime())
      .slice(0, 3); // Get only the 3 most recent files
  }, []);

  // Add this function to format the time difference
  const getTimeAgo = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffInSeconds = Math.floor((now.getTime() - date.getTime()) / 1000);

    if (diffInSeconds < 60) return 'just now';
    if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)}m ago`;
    if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)}h ago`;
    return `${Math.floor(diffInSeconds / 86400)}d ago`;
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
                {/* Recent Files Section */}
                <Box sx={{ mb: 4 }}>
                  <Typography
                    variant="h6"
                    sx={{
                      color: '#00ffff',
                      textShadow: '0 0 10px rgba(0, 255, 0, 0.5)',
                      mb: 2,
                      display: 'flex',
                      alignItems: 'center',
                      gap: 1,
                    }}
                  >
                    <AccessTimeIcon sx={{ color: '#00ff00' }} />
                    Recent Files
                  </Typography>
                  <Grid container spacing={2}>
                    {getRecentFiles.map((file) => (
                      <Grid item xs={12} md={4} key={file.id}>
                        <Card
                          sx={{
                            background: 'rgba(0, 0, 0, 0.5)',
                            border: '1px solid rgba(0, 255, 0, 0.2)',
                            borderRadius: 1,
                            transition: 'all 0.3s ease',
                            '&:hover': {
                              border: '1px solid rgba(0, 255, 0, 0.4)',
                              transform: 'translateY(-2px)',
                              boxShadow: '0 0 20px rgba(0, 255, 0, 0.2)',
                            },
                          }}
                        >
                          <CardContent>
                            <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                              <Box sx={{ mr: 2 }}>
                                {getFileIcon(file.name)}
                              </Box>
                              <Box sx={{ flexGrow: 1 }}>
                                <Typography
                                  variant="subtitle1"
                                  sx={{
                                    color: '#00ffff',
                                    fontWeight: 'bold',
                                    mb: 0.5,
                                  }}
                                >
                                  {file.name}
                                </Typography>
                                <Typography
                                  variant="body2"
                                  sx={{ color: 'rgba(0, 255, 0, 0.7)' }}
                                >
                                  {file.type.toUpperCase()} • {file.size}
                                </Typography>
                              </Box>
                            </Box>
                            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                              <Typography
                                variant="caption"
                                sx={{ color: 'rgba(0, 255, 0, 0.5)' }}
                              >
                                Modified {getTimeAgo(file.lastModified)}
                              </Typography>
                              <Box sx={{ display: 'flex', gap: 1 }}>
                                <Tooltip title="Download">
                                  <IconButton size="small" onClick={() => handleDownload(file.id)} sx={{ color: '#00ff00' }}>
                                    <DownloadIcon fontSize="small" />
                                  </IconButton>
                                </Tooltip>
                                <Tooltip title="Share">
                                  <IconButton size="small" onClick={() => handleShare(file.id)} sx={{ color: '#00ff00' }}>
                                    <ShareIcon fontSize="small" />
                                  </IconButton>
                                </Tooltip>
                              </Box>
                            </Box>
                          </CardContent>
                        </Card>
                      </Grid>
                    ))}
                  </Grid>
                </Box>

                <Divider sx={{ borderColor: 'rgba(0, 255, 0, 0.2)', my: 3 }} />

                {/* Existing Files Section */}
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
                  <Box sx={{ display: 'flex', gap: 2 }}>
                    <FormControl 
                      size="small" 
                      sx={{ 
                        minWidth: 120,
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
                        '& .MuiSelect-select': {
                          color: '#00ff00',
                        },
                        '& .MuiSvgIcon-root': {
                          color: '#00ff00',
                        },
                      }}
                    >
                      <InputLabel>Sort By</InputLabel>
                      <Select
                        value={sortBy}
                        label="Sort By"
                        onChange={handleSortChange}
                        startAdornment={
                          <InputAdornment position="start">
                            <SortIcon sx={{ color: '#00ff00' }} />
                          </InputAdornment>
                        }
                      >
                        <MenuItem value="name">Name</MenuItem>
                        <MenuItem value="date">Date</MenuItem>
                        <MenuItem value="size">Size</MenuItem>
                        <MenuItem value="type">Type</MenuItem>
                      </Select>
                    </FormControl>
                    <CyberButton startIcon={<UploadIcon />} onClick={() => setOpenUpload(true)}>
                      Upload File
                    </CyberButton>
                  </Box>
                </Box>
                <List>
                  {sortedAndFilteredFiles.map((file) => (
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
                        {getFileIcon(file.name)}
                      </ListItemIcon>
                      <ListItemText
                        primary={file.name}
                        secondary={`${file.type.toUpperCase()} • ${file.size} • ${new Date(file.date).toLocaleString()}`}
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

                <Box sx={{ display: 'flex', alignItems: 'center', mb: 4 }}>
                  <Box sx={{ position: 'relative' }}>
                    <Avatar
                      src={avatarPreview || profileData.avatar || undefined}
                      sx={{
                        width: 100,
                        height: 100,
                        bgcolor: '#00ff00',
                        fontSize: '2rem',
                        mr: 3,
                        border: '2px solid rgba(0, 255, 0, 0.3)',
                      }}
                    >
                      {!avatarPreview && !profileData.avatar && profileData.username.charAt(0).toUpperCase()}
                    </Avatar>
                    <input
                      accept="image/*"
                      style={{ display: 'none' }}
                      id="avatar-upload"
                      type="file"
                      onChange={handleAvatarChange}
                      disabled={!editMode}
                    />
                    <label htmlFor="avatar-upload">
                      <IconButton
                        component="span"
                        disabled={!editMode}
                        sx={{
                          position: 'absolute',
                          bottom: 0,
                          right: 0,
                          bgcolor: 'rgba(0, 0, 0, 0.8)',
                          border: '1px solid rgba(0, 255, 0, 0.3)',
                          '&:hover': {
                            bgcolor: 'rgba(0, 255, 0, 0.2)',
                          },
                        }}
                      >
                        <PhotoCameraIcon sx={{ color: '#00ff00' }} />
                      </IconButton>
                    </label>
                  </Box>
                  {avatarError && (
                    <Typography sx={{ color: '#ff0000', fontSize: '0.875rem', mt: 1 }}>
                      {avatarError}
                    </Typography>
                  )}
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
          <CyberButton onClick={() => setOpenUpload(false)}>
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
          <CyberButton onClick={() => setOpenShare(false)}>
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
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
              <Box sx={{ position: 'relative' }}>
                <Avatar
                  src={avatarPreview || profileData.avatar || undefined}
                  sx={{
                    width: 80,
                    height: 80,
                    bgcolor: '#00ff00',
                    fontSize: '1.5rem',
                    mr: 2,
                    border: '2px solid rgba(0, 255, 0, 0.3)',
                  }}
                >
                  {!avatarPreview && !profileData.avatar && profileData.username.charAt(0).toUpperCase()}
                </Avatar>
                <input
                  accept="image/*"
                  style={{ display: 'none' }}
                  id="avatar-upload"
                  type="file"
                  onChange={handleAvatarChange}
                  disabled={!editMode}
                />
                <label htmlFor="avatar-upload">
                  <IconButton
                    component="span"
                    disabled={!editMode}
                    sx={{
                      position: 'absolute',
                      bottom: 0,
                      right: 0,
                      bgcolor: 'rgba(0, 0, 0, 0.8)',
                      border: '1px solid rgba(0, 255, 0, 0.3)',
                      '&:hover': {
                        bgcolor: 'rgba(0, 255, 0, 0.2)',
                      },
                    }}
                  >
                    <PhotoCameraIcon sx={{ color: '#00ff00' }} />
                  </IconButton>
                </label>
              </Box>
              {avatarError && (
                <Typography sx={{ color: '#ff0000', fontSize: '0.875rem', mt: 1 }}>
                  {avatarError}
                </Typography>
              )}
            </Box>

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