import React, { useState, useEffect } from 'react';
import {
  Box, Container, Typography, Button, Paper, Grid, List, ListItem, ListItemText,
  ListItemIcon, IconButton, Dialog, DialogTitle, DialogContent, DialogActions,
  TextField, Tabs, Tab, Tooltip, Alert, Drawer, InputAdornment, Divider, Checkbox,
  LinearProgress
} from '@mui/material';
import {
  Upload as UploadIcon, Share as ShareIcon, Delete as DeleteIcon, Download as DownloadIcon,
  Folder as FolderIcon, Person as PersonIcon, Lock as LockIcon, LockOpen as LockOpenIcon,
  Search as SearchIcon, VerifiedUser as VerifiedUserIcon, People as PeopleIcon,
  Home as HomeIcon, Storage as StorageIcon, Security as SecurityIcon, Settings as SettingsIcon,
  Edit as EditIcon, Visibility as VisibilityIcon
} from '@mui/icons-material';
import { styled } from '@mui/material/styles';
import { useNavigate } from 'react-router-dom';
import { CyberButton, MatrixBackground } from '../components';
import { QRCodeSVG } from 'qrcode.react';
import { apiClient } from '../utils/apiClient';
import { encryptFile, generateFileKey, signChallenge, decryptFile, decryptKEK, generateOOBVerificationCode } from '../utils/crypto';
import { storage } from '../utils/storage';
import sodium from 'libsodium-wrappers-sumo';
import { generateEphemeralKeyPair, deriveX3DHSharedSecret, encryptWithAESGCM } from '../utils/crypto';

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
  { id: 1, name: 'document.pdf', type: 'pdf', size: '2.5 MB', shared: false, date: new Date('2024-03-15T10:30:00') },
  { id: 2, name: 'image.jpg', type: 'image', size: '1.8 MB', shared: true, date: new Date('2024-03-14T15:45:00') },
  { id: 3, name: 'code.zip', type: 'archive', size: '5.2 MB', shared: false, date: new Date('2024-03-13T09:20:00') },
  { id: 4, name: 'presentation.pptx', type: 'ppt', size: '4.1 MB', shared: false, date: new Date('2024-03-12T14:15:00') },
  { id: 5, name: 'notes.txt', type: 'text', size: '0.8 MB', shared: false, date: new Date('2024-03-11T11:00:00') },
  { id: 6, name: 'spreadsheet.xlsx', type: 'excel', size: '3.7 MB', shared: false, date: new Date('2024-03-10T16:30:00') },
].sort((a, b) => b.date.getTime() - a.date.getTime());

const mockSharedFiles = [
  { id: 4, name: 'shared_doc.pdf', type: 'pdf', size: '3.1 MB', sharedBy: 'user1', date: new Date('2024-03-15T13:20:00') },
  { id: 5, name: 'shared_image.jpg', type: 'image', size: '2.3 MB', sharedBy: 'user2', date: new Date('2024-03-14T17:45:00') },
  { id: 6, name: 'project_plan.docx', type: 'doc', size: '1.9 MB', sharedBy: 'user3', date: new Date('2024-03-13T08:30:00') },
  { id: 7, name: 'budget.xlsx', type: 'excel', size: '2.8 MB', sharedBy: 'user4', date: new Date('2024-03-12T10:15:00') },
  { id: 8, name: 'meeting_minutes.txt', type: 'text', size: '0.6 MB', sharedBy: 'user5', date: new Date('2024-03-11T14:00:00') },
].sort((a, b) => b.date.getTime() - a.date.getTime());

// Add interface for user data
interface UserData {
  id: number;
  username: string;
}

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

// Add this interface for file data
interface FileData {
  id: number;
  name: string;
  type: string;
  size: string;
  shared: boolean;
  date: Date;
}

// Add these interfaces
interface ChallengeResponse {
  status: string;
  nonce: string;
  detail?: string;
}

interface UploadResponse {
  status: string;
  message?: string;
  detail?: string;
}

// Add this interface for delete response
interface DeleteResponse {
  status: string;
  message?: string;
  detail?: string;
}

// First, let's define the proper types
interface PreKeyBundle {
  IK_pub: string;
  SPK_pub: string;
  SPK_signature: string;
}

interface RecipientKeyBundle {
  data: PreKeyBundle;
  verified: boolean;
  lastVerified?: string;
}

interface SelectedUser {
  id: number;
  username: string;
  prekeyBundle?: {
    IK_pub: string;
    SPK_pub: string;
    SPK_signature: string;
  };
}

const DEBUG = true; // Toggle for development

const logDebug = (message: string, data?: any) => {
  if (DEBUG) {
    console.log(`[Dashboard Debug] ${message}`, data ? data : '');
  }
};

function b64ToUint8Array(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

// Update the interface for the file list response
interface FileListResponse {
  status: string;
  files: Array<{
    filename: string;
    id: number;
    created_at: string;
  }>;
}

const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<'home'|'files'|'users'|'profile'>('home');
  const [searchQuery, setSearchQuery] = useState('');
  const [userSearchQuery, setUserSearchQuery] = useState('');
  const [openUpload, setOpenUpload] = useState(false);
  const [openShare, setOpenShare] = useState(false);
  const [selectedFile, setSelectedFile] = useState<number | null>(null);
  const [selectedRecipients, setSelectedRecipients] = useState<string[]>([]);
  const [openVerify, setOpenVerify] = useState(false);
  const [selectedUser, setSelectedUser] = useState<SelectedUser | null>(null);
  const [openProfileSettings, setOpenProfileSettings] = useState(false);
  const [profileData, setProfileData] = useState<ProfileData>(mockUserProfile);
  const [editMode, setEditMode] = useState(false);
  const [editedProfile, setEditedProfile] = useState<ProfileData>(mockUserProfile);
  const [verificationCode, setVerificationCode] = useState<string>('');
  const [files, setFiles] = useState<FileData[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isFetching, setIsFetching] = useState(false);
  const [openPreview, setOpenPreview] = useState(false);
  const [previewContent, setPreviewContent] = useState<string | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [previewImageUrl, setPreviewImageUrl] = useState<string | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const [users, setUsers] = useState<UserData[]>([]);
  const [loadingUsers, setLoadingUsers] = useState(false);
  const [userError, setUserError] = useState<string | null>(null);
  const [openDelete, setOpenDelete] = useState(false);
  const [fileToDelete, setFileToDelete] = useState<number | null>(null);

  // Get current user and their key bundle
  const currentUsername = storage.getCurrentUser();
  const keyBundle = React.useMemo(() => {
    if (!currentUsername) return null;
    return storage.getKeyBundle(currentUsername);
  }, [currentUsername]);

  const username = keyBundle?.username;
  const secretKey = keyBundle?.secretKey ? Uint8Array.from(atob(keyBundle.secretKey), c => c.charCodeAt(0)) : null;
  const pdk = keyBundle?.pdk ? Uint8Array.from(atob(keyBundle.pdk), c => c.charCodeAt(0)) : null;
  const kek = keyBundle?.kek ? Uint8Array.from(atob(keyBundle.kek), c => c.charCodeAt(0)) : null;

  // Add a ref to track if we've already fetched files
  const isMounted = React.useRef(false);
  const hasFetchedFiles = React.useRef(false);
  const mountCount = React.useRef(0);

  // Filter files based on search query
  const filteredFiles = mockFiles.filter(file => 
    file.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const handleTabChange = (event: React.SyntheticEvent, newValue: 'home'|'files'|'users'|'profile') => setActiveTab(newValue);
  const handleUpload = () => setOpenUpload(true);
  const handleShare = (fileId: number) => {
    logDebug('Share initiated', { fileId });
    setSelectedFile(fileId);
    setOpenShare(true);
  };
  const handleDelete = async (fileId: number) => {
    setFileToDelete(fileId);
    setOpenDelete(true);
  };
  const handleDeleteConfirm = async () => {
    if (!fileToDelete) return;
    
    try {
      setLoading(true);
      setError(null);
      logDebug('Starting file deletion', { fileId: fileToDelete });

      const file = files.find(f => f.id === fileToDelete);
      if (!file) {
        throw new Error('File not found');
      }

      // Step 1: Request challenge
      logDebug('Requesting challenge for delete');
      const challengeResponse = await apiClient.post<ChallengeResponse>('/challenge', {
        username,
        operation: 'delete_file'
      });
      logDebug('Delete challenge received', {
        status: challengeResponse.status,
        hasNonce: !!challengeResponse.nonce
      });

      if (challengeResponse.status !== 'challenge') {
        throw new Error(challengeResponse.detail || 'Failed to get challenge');
      }

      // Step 2: Sign the filename
      logDebug('Signing filename');
      const nonce = Uint8Array.from(atob(challengeResponse.nonce), c => c.charCodeAt(0));
      const signature = await signChallenge(new TextEncoder().encode(file.name), secretKey!);
      logDebug('Filename signed', {
        signatureLength: signature.length
      });

      // Step 3: Send delete request
      logDebug('Sending delete request');
      const deleteResponse = await apiClient.post<DeleteResponse>('/delete_file', {
        username,
        filename: file.name,
        nonce: challengeResponse.nonce,
        signature: btoa(String.fromCharCode.apply(null, Array.from(signature)))
      });
      logDebug('Delete response received', {
        status: deleteResponse.status,
        message: deleteResponse.message,
        detail: deleteResponse.detail
      });

      if (deleteResponse.status === 'ok') {
        logDebug('Delete successful, refreshing file list');
        hasFetchedFiles.current = false; // Reset the flag before refreshing
        await refreshFiles();
      } else {
        throw new Error(deleteResponse.detail || 'Delete failed');
      }
    } catch (err: any) {
      logDebug('Delete error', {
        errorType: err.constructor.name,
        message: err.message,
        hasResponse: !!err.response,
        responseData: err.response?.data
      });
      setError(err.message || 'Failed to delete file');
    } finally {
      setLoading(false);
      setOpenDelete(false);
      setFileToDelete(null);
      logDebug('Delete process completed');
    }
  };
  const handleDownload = async (fileId: number) => {
    const file = files.find(f => f.id === fileId);
    if (!file) return;
    setLoading(true);
    setError(null);

    try {
      // Step 1: Request challenge
      const challengeResponse = await apiClient.post<ChallengeResponse>('/challenge', {
        username,
        operation: 'download_file'
      });
      if (challengeResponse.status !== 'challenge') {
        throw new Error(challengeResponse.detail || 'Failed to get challenge');
      }
      // Step 2: Sign the filename
      const signature = await signChallenge(new TextEncoder().encode(file.name), secretKey!);
      // Step 3: Download file
      const downloadResponse = await apiClient.post<any>('/download_file', {
        username,
        filename: file.name,
        nonce: challengeResponse.nonce,
        signature: btoa(String.fromCharCode.apply(null, Array.from(signature)))
      });
      if (downloadResponse.status !== 'ok') {
        throw new Error(downloadResponse.detail || 'Failed to download file');
      }
      // Step 4: Decrypt file
      const encryptedFile = Uint8Array.from(atob(downloadResponse.encrypted_file), c => c.charCodeAt(0));
      const fileNonce = Uint8Array.from(atob(downloadResponse.file_nonce), c => c.charCodeAt(0));
      const dek = await decryptFileKey(downloadResponse.encrypted_dek, kek!, downloadResponse.dek_nonce);
      const decrypted = await decryptFile(encryptedFile, dek, fileNonce);

      // Step 5: Create a Blob and trigger download
      // Guess MIME type from extension
      let mime = 'application/octet-stream';
      if (isTextFile(file.name)) mime = 'text/plain';
      else if (/\.png$/i.test(file.name)) mime = 'image/png';
      else if (/\.jpe?g$/i.test(file.name)) mime = 'image/jpeg';
      else if (/\.gif$/i.test(file.name)) mime = 'image/gif';
      else if (/\.bmp$/i.test(file.name)) mime = 'image/bmp';
      else if (/\.webp$/i.test(file.name)) mime = 'image/webp';

      const blob = new Blob([decrypted], { type: mime });
      const url = URL.createObjectURL(blob);

      const a = document.createElement('a');
      a.href = url;
      a.download = file.name;
      document.body.appendChild(a);
      a.click();
      setTimeout(() => {
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }, 100);

    } catch (err: any) {
      setError(err.message || 'Failed to download file');
    } finally {
      setLoading(false);
    }
  };
  const handleRevoke = (fileId: number) => {
    logDebug('Revoke initiated', { fileId });
    // TODO: Implement revoke
  };
  const handleVerifyClick = async (user: { id: number; username: string }) => {
    try {
      // Get your own username and key bundle
      const myUsername = storage.getCurrentUser();
      if (!myUsername) {
        setUserError('No current user found in session storage.');
        return;
      }

      const myKeyBundle = storage.getKeyBundle(myUsername);
      if (!myKeyBundle || !myKeyBundle.IK_pub) {
        setUserError('Could not retrieve your identity key for verification.');
        return;
      }

      // Request challenge for get_prekey_bundle
      const challengeResponse = await apiClient.post<{ status: string; nonce: string }>('/challenge', {
        username: myUsername,
        operation: 'get_pre_key_bundle'
      });

      if (challengeResponse.status !== 'challenge') {
        setUserError('Failed to get challenge for verification.');
        return;
      }

      // Sign the nonce with your own secret key
      const nonce = Uint8Array.from(atob(challengeResponse.nonce), c => c.charCodeAt(0));
      const signature = await signChallenge(nonce, secretKey!);

      // Request the prekey bundle for the target user
      const prekeyResponse = await apiClient.post<{ 
        status: string;
        prekey_bundle: { 
          IK_pub: string;
          SPK_pub: string;
          SPK_signature: string;
        } 
      }>('/get_pre_key_bundle', {
        username: myUsername,
        target_username: user.username,
        nonce: challengeResponse.nonce,
        signature: btoa(String.fromCharCode.apply(null, Array.from(signature)))
      });

      // Store the pre-key bundle temporarily in state for later use
      setSelectedUser({
        ...user,
        prekeyBundle: prekeyResponse.prekey_bundle
      });

      // Generate and show the verification code
      const code = await generateOOBVerificationCode(myKeyBundle.IK_pub, prekeyResponse.prekey_bundle.IK_pub);
      setVerificationCode(code);
      setOpenVerify(true);

    } catch (err: any) {
      console.error('Verification error:', err);
      setUserError('Failed to fetch user key bundle or generate verification code.');
    }
  };

  // Add the verification confirmation handler
  const handleVerifyConfirm = async () => {
    try {
      const myUsername = storage.getCurrentUser();
      if (!myUsername || !selectedUser?.prekeyBundle) {
        throw new Error('Missing required data for verification');
      }

      const myKeyBundle = storage.getKeyBundle(myUsername);
      if (!myKeyBundle) {
        throw new Error('Could not retrieve your key bundle');
      }

      // Create the recipient key bundle with verified status
      const recipientKeyBundle: RecipientKeyBundle = {
        data: selectedUser.prekeyBundle,  // Store raw data directly
        verified: true
      };

      // Update the key bundle with the new verified recipient
      const updatedKeyBundle = {
        ...myKeyBundle,
        recipients: {
          ...(myKeyBundle.recipients || {}),
          [selectedUser.username]: recipientKeyBundle
        }
      };

      // Store the updated key bundle locally
      storage.saveKeyBundle(updatedKeyBundle);

      // Request challenge for backup_tofu
      const backupChallengeResponse = await apiClient.post<{ status: string; nonce: string }>('/challenge', {
        username: myUsername,
        operation: 'backup_tofu'
      });

      if (backupChallengeResponse.status !== 'challenge') {
        throw new Error('Failed to get challenge for backup');
      }

      // Sign the nonce for backup
      const backupNonce = Uint8Array.from(atob(backupChallengeResponse.nonce), c => c.charCodeAt(0));
      const backupSignature = await signChallenge(backupNonce, secretKey!);

      // Create backup data with all necessary keys
      const backupData = {
        username: myUsername,
        // Private keys
        IK_priv: myKeyBundle.IK_priv,
        SPK_priv: myKeyBundle.SPK_priv,
        OPKs_priv: myKeyBundle.OPKs_priv,
        // Public keys
        IK_pub: myKeyBundle.IK_pub,
        SPK_pub: myKeyBundle.SPK_pub,
        SPK_signature: myKeyBundle.SPK_signature,
        OPKs: myKeyBundle.OPKs,
        // Additional keys
        secretKey: myKeyBundle.secretKey,
        pdk: myKeyBundle.pdk,
        kek: myKeyBundle.kek,
        // Add the recipients with base64 encoded data
        recipients: updatedKeyBundle.recipients,
        verified: true,
        lastVerified: new Date().toISOString()
      };

      // Generate a new nonce for the backup encryption
      const encryptionNonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
      
      // Encrypt the backup with the PDK
      const encryptedBackup = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        JSON.stringify(backupData),
        null,
        null,
        encryptionNonce,
        pdk!
      );

      // Send the backup to the server
      await apiClient.post('/backup_tofu', {
        username: myUsername,
        encrypted_backup: btoa(String.fromCharCode.apply(null, Array.from(encryptedBackup))),
        backup_nonce: btoa(String.fromCharCode.apply(null, Array.from(encryptionNonce))),
        nonce: backupChallengeResponse.nonce,
        signature: btoa(String.fromCharCode.apply(null, Array.from(backupSignature)))
      });

      // Close the verification dialog
      setOpenVerify(false);
      setSelectedUser(null);
      setVerificationCode('');

    } catch (err: any) {
      console.error('Verification confirmation error:', err);
      setUserError('Failed to confirm verification and update backup.');
    }
  };

  // Update the fetchFiles function
  const fetchFiles = async () => {
    if (isFetching || !isMounted.current) {
      logDebug('Fetch already in progress or component unmounted, skipping');
      return;
    }
    
    try {
      setIsFetching(true);
      setLoading(true);
      setError(null);

      logDebug('Starting file fetch', {
        username,
        hasSecretKey: !!secretKey,
        hasPdk: !!pdk,
        hasKek: !!kek,
        hasFetchedBefore: hasFetchedFiles.current,
        isMounted: isMounted.current
      });

      // Request challenge
      const challengeResponse = await apiClient.post<ChallengeResponse>('/challenge', {
        username,
        operation: 'list_files'
      });

      logDebug('Challenge response received', {
        status: challengeResponse.status,
        hasNonce: !!challengeResponse.nonce,
        detail: challengeResponse.detail
      });

      if (challengeResponse.status !== 'challenge') {
        throw new Error(challengeResponse.detail || 'Failed to get challenge');
      }

      // Sign the nonce
      const nonce = Uint8Array.from(atob(challengeResponse.nonce), c => c.charCodeAt(0));
      const signature = await signChallenge(nonce, secretKey!);

      // List files
      const listResponse = await apiClient.post<FileListResponse>('/list_files', {
        username,
        nonce: challengeResponse.nonce,
        signature: btoa(String.fromCharCode.apply(null, Array.from(signature)))
      });

      logDebug('File list response received', {
        status: listResponse.status,
        fileCount: listResponse.files?.length
      });

      if (listResponse.status === 'ok' && isMounted.current) {
        const fileData: FileData[] = listResponse.files.map(file => {
          if (!file || !file.filename) {
            logDebug('Invalid file data received', { file });
            throw new Error('Invalid file data received from server');
          }
          return {
            id: file.id,
            name: file.filename,
            type: file.filename.split('.').pop() || 'unknown',
            size: '0 KB', // Size not provided in response
            shared: false, // Shared status not provided in response
            date: new Date(file.created_at)
          };
        });
        setFiles(fileData);
        hasFetchedFiles.current = true;
        logDebug('Files processed successfully', { fileCount: fileData.length });
      } else if (!isMounted.current) {
        logDebug('Component unmounted during fetch, skipping state update');
      } else {
        throw new Error('Failed to list files');
      }
    } catch (err: any) {
      if (isMounted.current) {
        logDebug('Error in fetchFiles', {
          errorType: err.constructor.name,
          message: err.message,
          hasResponse: !!err.response,
          responseData: err.response?.data,
          stack: err.stack
        });
        setError(err.message || 'Failed to list files');
      }
    } finally {
      if (isMounted.current) {
        setLoading(false);
        setIsFetching(false);
        logDebug('File fetch completed');
      }
    }
  };

  // Update the useEffect hook
  useEffect(() => {
    mountCount.current++;
    isMounted.current = true;
    
    logDebug('Dashboard mounted', {
      username,
      hasPdk: !!pdk,
      isFetching,
      hasFetchedBefore: hasFetchedFiles.current,
      isMounted: isMounted.current,
      mountCount: mountCount.current
    });

    const loadFiles = async () => {
      // Only fetch on the first mount
      if (mountCount.current > 1) {
        logDebug('Skipping file load on subsequent mount', {
          mountCount: mountCount.current
        });
        return;
      }

      if (!username || !pdk || isFetching) {
        logDebug('Skipping file load', {
          hasUsername: !!username,
          hasPdk: !!pdk,
          isFetching
        });
        return;
      }

      try {
        await fetchFiles();
      } catch (error) {
        if (isMounted.current) {
          logDebug('Error in loadFiles', { error });
        }
      }
    };

    loadFiles();

    return () => {
      isMounted.current = false;
      logDebug('Dashboard unmounted', {
        mountCount: mountCount.current
      });
    };
  }, [username, pdk]); // Keep these dependencies

  // Update the refreshFiles function
  const refreshFiles = async () => {
    if (!username || !pdk || isFetching || !isMounted.current) return;
    hasFetchedFiles.current = false;
    await fetchFiles();
  };

  // Update handleFileUpload to use the same pattern
  const handleFileUpload = async (file: File) => {
    try {
      setLoading(true);
      setError(null);
      logDebug('Starting file upload', {
        fileName: file.name,
        fileSize: file.size,
        fileType: file.type
      });

      // Step 1: Request challenge
      logDebug('Requesting challenge for upload');
      const challengeResponse = await apiClient.post<ChallengeResponse>('/challenge', {
        username,
        operation: 'upload_file'
      });
      logDebug('Upload challenge received', {
        status: challengeResponse.status,
        hasNonce: !!challengeResponse.nonce
      });

      if (challengeResponse.status !== 'challenge') {
        throw new Error(challengeResponse.detail || 'Failed to get challenge');
      }

      // Step 2: Generate file key and encrypt file
      logDebug('Generating file key');
      const fileKey = await generateFileKey();
      const fileNonce = new Uint8Array(24);
      window.crypto.getRandomValues(fileNonce);
      logDebug('File key generated', {
        keyLength: fileKey.length,
        nonceLength: fileNonce.length
      });

      logDebug('Reading file data');
      const fileData = await file.arrayBuffer();
      logDebug('Encrypting file', {
        fileSize: fileData.byteLength
      });
      const encryptedFile = await encryptFile(new Uint8Array(fileData), fileKey, fileNonce);
      logDebug('File encrypted', {
        encryptedSize: encryptedFile.length
      });

      // Step 3: Encrypt file key with KEK
      logDebug('Encrypting file key with KEK');
      const kekNonce = new Uint8Array(24);
      window.crypto.getRandomValues(kekNonce);
      const encryptedDek = await encryptFile(fileKey, kek!, kekNonce);
      logDebug('File key encrypted', {
        encryptedDekLength: encryptedDek.length,
        kekNonceLength: kekNonce.length
      });

      // Step 4: Sign the encrypted DEK
      logDebug('Signing encrypted DEK');
      const nonce = Uint8Array.from(atob(challengeResponse.nonce), c => c.charCodeAt(0));
      const signature = await signChallenge(encryptedDek, secretKey!);
      logDebug('DEK signed', {
        signatureLength: signature.length
      });

      // Step 5: Upload the file
      logDebug('Sending upload request');
      const uploadResponse = await apiClient.post<UploadResponse>('/upload_file', {
        username,
        filename: file.name,
        encrypted_file: btoa(String.fromCharCode.apply(null, Array.from(encryptedFile))),
        file_nonce: btoa(String.fromCharCode.apply(null, Array.from(fileNonce))),
        encrypted_dek: btoa(String.fromCharCode.apply(null, Array.from(encryptedDek))),
        dek_nonce: btoa(String.fromCharCode.apply(null, Array.from(kekNonce))),
        nonce: challengeResponse.nonce,
        signature: btoa(String.fromCharCode.apply(null, Array.from(signature)))
      });
      logDebug('Upload response received', {
        status: uploadResponse.status,
        message: uploadResponse.message,
        detail: uploadResponse.detail
      });

      if (uploadResponse.status === 'ok') {
        logDebug('Upload successful, refreshing file list');
        hasFetchedFiles.current = false; // Reset the flag before refreshing
        await refreshFiles();
        setOpenUpload(false);
      } else {
        throw new Error(uploadResponse.detail || 'Upload failed');
      }
    } catch (err: any) {
      logDebug('Upload error', {
        errorType: err.constructor.name,
        message: err.message,
        hasResponse: !!err.response,
        responseData: err.response?.data
      });
      setError(err.message || 'Failed to upload file');
    } finally {
      setLoading(false);
      logDebug('Upload process completed');
    }
  };

  // Helper to check if file is text-based
  const isTextFile = (filename: string) => {
    return /\.(txt|json|js|ts|md|env|csv|log|html|css|xml)$/i.test(filename);
  };

  // Helper to check if file is an image
  const isImageFile = (filename: string) => {
    return /\.(png|jpg|jpeg|gif|bmp|webp)$/i.test(filename);
  };

  // Preview handler
  const handlePreview = async (fileId: number) => {
    const file = files.find(f => f.id === fileId);
    if (!file) return;
    setOpenPreview(true);
    setPreviewContent(null);
    setPreviewImageUrl(null);
    setPreviewError(null);
    setPreviewLoading(true);

    if (!isTextFile(file.name) && !isImageFile(file.name)) {
      setPreviewContent(null);
      setPreviewImageUrl(null);
      setPreviewError('Preview not available for this file type.');
      setPreviewLoading(false);
      return;
    }

    try {
      // Step 1: Request challenge
      const challengeResponse = await apiClient.post<ChallengeResponse>('/challenge', {
        username,
        operation: 'download_file'
      });
      if (challengeResponse.status !== 'challenge') {
        throw new Error(challengeResponse.detail || 'Failed to get challenge');
      }
      // Step 2: Sign the filename
      const signature = await signChallenge(new TextEncoder().encode(file.name), secretKey!);
      // Step 3: Download file
      const downloadResponse = await apiClient.post<any>('/download_file', {
        username,
        filename: file.name,
        nonce: challengeResponse.nonce,
        signature: btoa(String.fromCharCode.apply(null, Array.from(signature)))
      });
      if (downloadResponse.status !== 'ok') {
        throw new Error(downloadResponse.detail || 'Failed to download file');
      }
      // Step 4: Decrypt file
      const encryptedFile = Uint8Array.from(atob(downloadResponse.encrypted_file), c => c.charCodeAt(0));
      const fileNonce = Uint8Array.from(atob(downloadResponse.file_nonce), c => c.charCodeAt(0));
      const dek = await decryptFileKey(downloadResponse.encrypted_dek, kek!, downloadResponse.dek_nonce);
      const decrypted = await decryptFile(encryptedFile, dek, fileNonce);

      if (isTextFile(file.name)) {
        const text = new TextDecoder('utf-8').decode(decrypted);
        setPreviewContent(text);
        setPreviewImageUrl(null);
      } else if (isImageFile(file.name)) {
        // Guess MIME type from extension
        let mime = 'image/png';
        if (/\.jpe?g$/i.test(file.name)) mime = 'image/jpeg';
        else if (/\.gif$/i.test(file.name)) mime = 'image/gif';
        else if (/\.bmp$/i.test(file.name)) mime = 'image/bmp';
        else if (/\.webp$/i.test(file.name)) mime = 'image/webp';
        const blob = new Blob([decrypted], { type: mime });
        const url = URL.createObjectURL(blob);
        setPreviewImageUrl(url);
        setPreviewContent(null);
      }
    } catch (err: any) {
      setPreviewError(err.message || 'Failed to preview file');
    } finally {
      setPreviewLoading(false);
    }
  };

  // Helper to decrypt file key
  const decryptFileKey = async (b64Dek: string, kek: Uint8Array, b64DekNonce: string) => {
    const dek = Uint8Array.from(atob(b64Dek), c => c.charCodeAt(0));
    const dekNonce = Uint8Array.from(atob(b64DekNonce), c => c.charCodeAt(0));
    return await decryptKEK(dek, kek, dekNonce);
  };

  // Drag and drop handlers
  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      await handleFileUpload(file);
    }
  };

  // Add function to fetch users
  const fetchUsers = async () => {
    try {
      setLoadingUsers(true);
      setUserError(null);

      // Step 1: Request challenge
      const challengeResponse = await apiClient.post<ChallengeResponse>('/challenge', {
        username,
        operation: 'list_users'
      });

      if (challengeResponse.status !== 'challenge') {
        throw new Error(challengeResponse.detail || 'Failed to get challenge');
      }

      // Step 2: Sign the nonce
      const nonce = Uint8Array.from(atob(challengeResponse.nonce), c => c.charCodeAt(0));
      const signature = await signChallenge(nonce, secretKey!);

      // Step 3: Get user list
      const listResponse = await apiClient.post<{ status: string; users: UserData[] }>('/list_users', {
        username,
        nonce: challengeResponse.nonce,
        signature: btoa(String.fromCharCode.apply(null, Array.from(signature)))
      });

      if (listResponse.status === 'ok') {
        setUsers(listResponse.users);
      } else {
        throw new Error('Failed to list users');
      }
    } catch (err: any) {
      setUserError(err.message || 'Failed to fetch users');
    } finally {
      setLoadingUsers(false);
    }
  };

  // Update useEffect to fetch users when needed
  useEffect(() => {
    if (activeTab === 'users' && username && secretKey && !loadingUsers && !users.length) {
      fetchUsers();
    }
  }, [activeTab]); // Only depend on activeTab changes

  // Add a function to manually refresh users
  const refreshUsers = () => {
    if (username && secretKey) {
      fetchUsers();
    }
  };

  const handleProfileCancel = () => {
    setEditMode(false);
    setEditedProfile(profileData);
  };

  const handleProfileSave = () => {
    setProfileData(editedProfile);
    setEditMode(false);
  };

  const handleProfileEdit = () => {
    setEditMode(true);
    setEditedProfile(profileData);
  };

  const debugSection = (
    <Box sx={{ 
      p: 2, 
      mb: 2,
      bgcolor: 'rgba(0,0,0,0.8)', 
      color: '#00ff00', 
      fontFamily: 'monospace',
      border: '1px solid rgba(0, 255, 0, 0.2)',
      borderRadius: 1
    }}>
      <Typography variant="h6" sx={{ color: '#00ffff', mb: 1 }}>Debug Info:</Typography>
      <Typography>Username: {username}</Typography>
      <Typography>Secret Key: {secretKey ? 'Present' : 'Not set'}</Typography>
      <Typography>PDK: {pdk ? 'Present' : 'Not set'}</Typography>
      <Typography>KEK: {kek ? 'Present' : 'Not set'}</Typography>
    </Box>
  );

  const handleShareConfirm = async () => {
    if (!selectedFile || selectedRecipients.length === 0) return;
    setLoading(true);
    setError(null);

    try {
      const file = files.find(f => f.id === selectedFile);
      if (!file) throw new Error('File not found');

      // 1. Get the DEK for this file
      const challengeResponse = await apiClient.post<ChallengeResponse>('/challenge', {
        username,
        operation: 'retrieve_file_dek'
      });

      if (challengeResponse.status !== 'challenge') {
        throw new Error(challengeResponse.detail || 'Failed to get challenge');
      }

      // Sign the nonce 
      const signature = await signChallenge(b64ToUint8Array(challengeResponse.nonce), secretKey!);

      // Get the encrypted DEK
      const dekResponse = await apiClient.post<{ status: string; encrypted_dek: string; dek_nonce: string }>('/retrieve_file_dek', {
        username,
        file_id: selectedFile,
        nonce: challengeResponse.nonce,
        signature: btoa(String.fromCharCode.apply(null, Array.from(signature)))
      });

      if (dekResponse.status !== 'ok') {
        throw new Error('Failed to retrieve file key');
      }

      // Decrypt the file key using the KEK from our keyBundle
      const fileKey = await decryptFileKey(dekResponse.encrypted_dek, kek!, dekResponse.dek_nonce);
      
      for (const recipientUsername of selectedRecipients) {
        // 2. Get recipient's verified pre-key bundle from local storage
        const myUsername = storage.getCurrentUser();
        if (!myUsername) throw new Error('No current user found');
        const myKeyBundle = storage.getKeyBundle(myUsername);
        if (!myKeyBundle) throw new Error('Key bundle not found for current user');
        const storedRecipientBundle = myKeyBundle.recipients?.[recipientUsername]?.data;
        if (!storedRecipientBundle) throw new Error('Recipient bundle not found or not verified');

        // 3. Get fresh key bundle from server for TOFU check
        const bundleChallengeResponse = await apiClient.post<ChallengeResponse>('/challenge', {
          username: myUsername,
          operation: 'get_pre_key_bundle'
        });

        if (bundleChallengeResponse.status !== 'challenge') {
          throw new Error('Failed to get challenge for key bundle');
        }

        const bundleSignature = await signChallenge(b64ToUint8Array(bundleChallengeResponse.nonce), secretKey!);
        const freshBundleResponse = await apiClient.post<{ status: string; prekey_bundle: any }>('/get_pre_key_bundle', {
          username: myUsername,
          target_username: recipientUsername,
          nonce: bundleChallengeResponse.nonce,
          signature: btoa(String.fromCharCode.apply(null, Array.from(bundleSignature)))
        });

        if (freshBundleResponse.status !== 'ok') {
          throw new Error('Failed to get fresh key bundle');
        }

        // 4. Compare stored bundle with fresh bundle for TOFU
        const freshBundle = freshBundleResponse.prekey_bundle;
        if (freshBundle.IK_pub !== storedRecipientBundle.IK_pub ||
            freshBundle.SPK_pub !== storedRecipientBundle.SPK_pub ||
            freshBundle.SPK_signature !== storedRecipientBundle.SPK_signature) {
          throw new Error('Key bundle mismatch - possible security issue');
        }

        // 5. Get OPK for recipient
        const opkChallengeResponse = await apiClient.post<ChallengeResponse>('/challenge', {
          username: myUsername,  // Use requesting user's username for challenge
          operation: 'get_opk'
        });

        if (opkChallengeResponse.status !== 'challenge') {
          throw new Error('Failed to get challenge for OPK');
        }

        const opkSignature = await signChallenge(b64ToUint8Array(opkChallengeResponse.nonce), secretKey!);
        const opkResponse = await apiClient.post<{ status: string; opk_id: number; pre_key: string }>('/opk', {
          username: myUsername,  // Use requesting user's username for signature verification
          target_username: recipientUsername,  // Add target_username for getting their OPK
          nonce: opkChallengeResponse.nonce,
          signature: btoa(String.fromCharCode.apply(null, Array.from(opkSignature)))
        });

        if (opkResponse.status !== 'ok') {
          throw new Error('Failed to get OPK');
        }

        // 6. Generate ephemeral X25519 key pair
        const ephemeralKeyPair = await generateEphemeralKeyPair();

        // 7. Derive X3DH shared secret
        const sharedSecret = await deriveX3DHSharedSecret({
          myIKPriv: b64ToUint8Array(myKeyBundle.IK_priv),
          myEKPriv: ephemeralKeyPair.privateKey,
          recipientIKPub: b64ToUint8Array(freshBundle.IK_pub),
          recipientSPKPub: b64ToUint8Array(freshBundle.SPK_pub),
          recipientSPKSignature: b64ToUint8Array(freshBundle.SPK_signature),
        });

        // 8. Encrypt the file key (DEK) with the shared secret
        const { ciphertext, nonce } = await encryptWithAESGCM(sharedSecret, fileKey);

        // 9. Request challenge for share_file
        const shareChallengeResponse = await apiClient.post<{ status: string; nonce: string; detail?: string }>('/challenge', {
          username,
          operation: 'share_file'
        });

        if (shareChallengeResponse.status !== 'challenge') {
          throw new Error('Failed to get challenge for sharing');
        }

        // 10. Sign the encrypted file key
        if (!secretKey) throw new Error('Secret key not available');
        const shareSignature = await signChallenge(ciphertext, secretKey);

        // 11. Send /share_file request with OPK
        await apiClient.post('/share_file', {
          username,
          file_id: selectedFile,
          recipient_username: recipientUsername,
          EK_pub: btoa(String.fromCharCode.apply(null, Array.from(ephemeralKeyPair.publicKey))),
          IK_pub: myKeyBundle.IK_pub,
          encrypted_file_key: btoa(String.fromCharCode.apply(null, Array.from(ciphertext))),
          OPK_ID: opkResponse.opk_id,
          nonce: shareChallengeResponse.nonce,
          signature: btoa(String.fromCharCode.apply(null, Array.from(shareSignature)))
        });
      }

      setOpenShare(false);
      setSelectedRecipients([]);
      // Optionally show a success message

    } catch (err: any) {
      setError(err.message || 'Failed to share file');
    } finally {
      setLoading(false);
    }
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
            {debugSection}

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
                    Users
                  </Typography>
                  <Grid container spacing={2}>
                    {users
                      .slice(0, 6)
                      .map((user) => (
                        <Grid item xs={4} sm={2} key={user.id}>
                          <Paper
                            sx={{
                              p: 2,
                              textAlign: 'center',
                              background: 'rgba(0,0,0,0.6)',
                            }}
                          >
                            <PersonIcon sx={{ fontSize: 32, color: '#00ff00' }} />
                            <Typography
                              sx={{ mt: 1, color: '#00ffff', fontSize: '0.875rem' }}
                            >
                              {user.username}
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
                    {files
                      .slice()
                      .sort((a, b) => b.date.getTime() - a.date.getTime())
                      .slice(0, 10)
                      .map((f) => (
                        <ListItem
                          key={f.id}
                          sx={{
                            mb: 1,
                            border: '1px solid rgba(0,255,0,0.2)',
                            borderRadius: 1,
                            transition: 'all 0.3s ease',
                            '&:hover': {
                              border: '1px solid rgba(0,255,0,0.4)',
                              backgroundColor: 'rgba(0,255,0,0.05)',
                              boxShadow: '0 0 20px rgba(0,255,0,0.2)',
                            },
                          }}
                        >
                          <ListItemIcon>
                            <FolderIcon sx={{ color: '#00ff00' }} />
                          </ListItemIcon>
                          <ListItemText
                            primary={f.name}
                            secondary={`${f.type.toUpperCase()} • ${f.size} • ${f.date.toLocaleDateString('en-GB')} ${f.date.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })}`}
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
                        <Tooltip title="Preview">
                          <IconButton onClick={() => handlePreview(file.id)} sx={{ color: '#00ff00' }}>
                            <VisibilityIcon />
                          </IconButton>
                        </Tooltip>
                      </Box>
                    </ListItem>
                  ))}
                </List>
                )}
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
                    Users
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
                {loadingUsers ? (
                  <Box sx={{ textAlign: 'center', py: 4 }}>
                    <Typography sx={{ color: '#00ff00' }}>Loading users...</Typography>
                  </Box>
                ) : userError ? (
                  <Alert severity="error" sx={{ bgcolor: 'rgba(255, 0, 0, 0.1)' }}>
                    {userError}
                  </Alert>
                ) : users.length === 0 ? (
                  <Box sx={{ textAlign: 'center', py: 4 }}>
                    <Typography sx={{ color: '#00ff00' }}>No users found.</Typography>
                  </Box>
                ) : (
                  <List>
                    {users
                      .filter(user => user.username.toLowerCase().includes(userSearchQuery.toLowerCase()))
                      .map((user) => (
                        <ListItem
                          key={user.id}
                          sx={{
                            border: '1px solid rgba(0, 255, 0, 0.2)',
                            borderRadius: 1,
                            mb: 1,
                            display: 'flex',
                            alignItems: 'center',
                            '&:hover': {
                              border: '1px solid rgba(0, 255, 0, 0.4)',
                              backgroundColor: 'rgba(0, 255, 0, 0.05)',
                            },
                          }}
                        >
                          <ListItemIcon>
                            <PersonIcon sx={{ color: '#00ff00' }} />
                          </ListItemIcon>
                          <ListItemText
                            primary={user.username}
                            primaryTypographyProps={{
                              sx: { color: '#00ffff', fontWeight: 'bold' },
                            }}
                          />
                          <Box sx={{ ml: 'auto' }}>
                            <Button
                              variant="contained"
                              color="primary"
                              onClick={() => handleVerifyClick({ id: user.id, username: user.username })}
                              size="small"
                              sx={{ minWidth: 100, fontSize: '0.95rem', height: 36, px: 2.5, py: 1 }}
                            >
                              Verify
                            </Button>
                          </Box>
                        </ListItem>
                      ))}
                  </List>
                )}
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
        onClose={() => {
          if (!loading) {
            setOpenUpload(false);
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
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
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
                  handleFileUpload(file);
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
            onClick={() => setOpenUpload(false)}
            sx={{ color: 'rgba(0, 255, 0, 0.7)' }}
            disabled={loading}
          >
            Cancel
          </Button>
        </DialogActions>
      </Dialog>

      {/* Share Dialog */}
      <Dialog
        open={openShare}
        onClose={() => {
          setOpenShare(false);
          setSelectedRecipients([]);
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
          
          {(() => {
            const myUsername = storage.getCurrentUser();
            const myKeyBundle = myUsername ? storage.getKeyBundle(myUsername) : null;
            const verifiedRecipients = myKeyBundle?.recipients 
              ? Object.entries(myKeyBundle.recipients)
                  .filter(([_, bundle]) => bundle.verified)
                  .reduce<{ [username: string]: RecipientKeyBundle }>((acc, [username, bundle]) => ({
                    ...acc,
                    [username]: bundle as RecipientKeyBundle
                  }), {})
              : {};

            return Object.keys(verifiedRecipients).length === 0 ? (
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
                      onClick={() => setSelectedRecipients([])}
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
                  {Object.entries(verifiedRecipients).map(([username, bundle]: [string, RecipientKeyBundle]) => (
                    <ListItem
                      key={username}
                      button
                      onClick={() => {
                        setSelectedRecipients(prev => 
                          prev.includes(username)
                            ? prev.filter(u => u !== username)
                            : [...prev, username]
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
                        secondary={`Verified on ${new Date(bundle.lastVerified || '').toLocaleDateString()}`}
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
            );
          })()}
        </DialogContent>
        <DialogActions sx={{ borderTop: '1px solid rgba(0, 255, 0, 0.2)', p: 2 }}>
          <Button 
            onClick={() => {
              setOpenShare(false);
              setSelectedRecipients([]);
            }}
            sx={{ color: 'rgba(0, 255, 0, 0.7)' }}
          >
            Cancel
          </Button>
          <CyberButton
            onClick={handleShareConfirm}
            size="small"
            sx={{ minWidth: 100, fontSize: '0.95rem', height: 36, px: 2.5, py: 1 }}
            disabled={selectedRecipients.length === 0}
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
            onClick={handleVerifyConfirm}
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

      {/* Preview Dialog */}
      <Dialog
        open={openPreview}
        onClose={() => setOpenPreview(false)}
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
          <Button onClick={() => setOpenPreview(false)} sx={{ color: 'rgba(0, 255, 0, 0.7)' }}>
            Close
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog
        open={openDelete}
        onClose={() => {
          if (!loading) {
            setOpenDelete(false);
            setFileToDelete(null);
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
            onClick={() => {
              setOpenDelete(false);
              setFileToDelete(null);
            }}
            sx={{ color: 'rgba(0, 255, 0, 0.7)' }}
            disabled={loading}
          >
            Cancel
          </Button>
          <CyberButton
            onClick={handleDeleteConfirm}
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
    </>
  );
};

export default Dashboard;