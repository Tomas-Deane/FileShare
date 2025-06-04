import React, { useState, useEffect, useRef } from 'react';
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
  Edit as EditIcon, Visibility as VisibilityIcon, Refresh as RefreshIcon
} from '@mui/icons-material';
import { styled } from '@mui/material/styles';
import { useNavigate } from 'react-router-dom';
import { CyberButton, MatrixBackground } from '../components';
import { QRCodeSVG } from 'qrcode.react';
import { apiClient } from '../utils/apiClient';
import { encryptFile, generateFileKey, signChallenge, decryptFile, decryptKEK, generateOOBVerificationCode } from '../utils/crypto';
import { storage } from '../utils/storage';
import sodium from 'libsodium-wrappers-sumo';
import { generateEphemeralKeyPair, deriveX3DHSharedSecret, encryptWithAESGCM, deriveX3DHSharedSecretRecipient, encryptWithPublicKey } from '../utils/crypto';
import { testX3DHKeyExchange } from '../utils/crypto';

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

// Add this interface near the top with other interfaces
interface SharedFileData {
  id: number;
  share_id: number;  // Add this
  filename: string;
  shared_by: string;
  created_at: string;
}

const DEBUG = true; // Toggle for development

const logDebug = (message: string, data?: any) => {
  if (DEBUG) {
    console.log(`[Dashboard Debug] ${message}`, data ? data : '');
  }
};

function b64ToUint8Array(b64: string | undefined | null): Uint8Array {
  if (!b64) {
    console.error('Attempted to decode undefined or null base64 string');
    throw new Error('Invalid base64 string: value is undefined or null');
  }
  
  // Replace URL-safe characters back to standard base64
  const standardB64 = b64.replace(/-/g, '+').replace(/_/g, '/');
  
  // Add padding if needed
  const paddedB64 = standardB64.padEnd(standardB64.length + (4 - (standardB64.length % 4)) % 4, '=');
  
  try {
    return Uint8Array.from(atob(paddedB64), c => c.charCodeAt(0));
  } catch (error) {
    console.error('Base64 decoding error:', error);
    console.error('Input string:', b64);
    console.error('Padded string:', paddedB64);
    throw new Error('Invalid base64 string: failed to decode');
  }
}

function uint8ArrayToB64(bytes: Uint8Array): string {
  // Use standard base64 encoding without URL-safe modifications
  return btoa(String.fromCharCode.apply(null, Array.from(bytes)));
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

interface DownloadResponse {
  status: string;
  detail?: string;
  encrypted_file?: string;
  file_nonce?: string;
  encrypted_file_key?: string;
  file_key_nonce?: string;  // Add this field
  EK_pub?: string;
  IK_pub?: string;
  SPK_pub?: string;
  SPK_signature?: string;
  opk_id?: number;
  pre_key?: string;
}

const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const test_empty_opk_share = false; // Set to false to disable testing empty OPK sharing
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
  const [sharedFiles, setSharedFiles] = useState<SharedFileData[]>([]);
  const [loadingSharedFiles, setLoadingSharedFiles] = useState(false);
  const [openNoOPKConfirm, setOpenNoOPKConfirm] = useState(false);
  const [pendingShare, setPendingShare] = useState<{recipient: string, fileKey: Uint8Array, freshBundle: any} | null>(null);
  const [openUnverifiedSender, setOpenUnverifiedSender] = useState(false);
  const [unverifiedSenderFile, setUnverifiedSenderFile] = useState<{id: number, sender: string} | null>(null);

  // Get current user and their key bundle
  const currentUsername = storage.getCurrentUser();
  const keyBundle = React.useMemo(() => {
    if (!currentUsername) {
      console.log('No current username found');
      return null;
    }
    const bundle = storage.getKeyBundle(currentUsername);
    console.log('Retrieved key bundle:', {
      hasBundle: !!bundle,
      hasKEK: !!bundle?.kek,
      kekLength: bundle?.kek?.length
    });
    return bundle;
  }, [currentUsername]);

  const username = keyBundle?.username;
  const secretKey = keyBundle?.secretKey ? Uint8Array.from(atob(keyBundle.secretKey), c => c.charCodeAt(0)) : null;
  const pdk = keyBundle?.pdk ? Uint8Array.from(atob(keyBundle.pdk), c => c.charCodeAt(0)) : null;
  const kek = keyBundle?.kek ? Uint8Array.from(atob(keyBundle.kek), c => c.charCodeAt(0)) : null;

  console.log('Key bundle state:', {
    hasUsername: !!username,
    hasSecretKey: !!secretKey,
    hasPDK: !!pdk,
    hasKEK: !!kek,
    kekLength: kek?.length
  });

  // Add a ref to track if we've already fetched files
  const isMounted = React.useRef(false);
  const hasFetchedFiles = React.useRef(false);
  const mountCount = React.useRef(0);

  // Add this ref near the top of the component with other refs
  const hasFetchedSharedFiles = React.useRef(false);

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

      // Step 2: Sign the file ID
      logDebug('Signing file ID');
      const nonce = Uint8Array.from(atob(challengeResponse.nonce), c => c.charCodeAt(0));
      const signature = await signChallenge(new TextEncoder().encode(fileToDelete.toString()), secretKey!);
      logDebug('File ID signed', {
        signatureLength: signature.length
      });

      // Step 3: Send delete request
      logDebug('Sending delete request');
      const deleteResponse = await apiClient.post<DeleteResponse>('/delete_file', {
        username,
        file_id: fileToDelete,
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
  const handleDownload = async (fileId: number, isShared: boolean = false) => {
    setLoading(true);
    setError(null);

    try {
      // Get file information
      const file = isShared 
        ? sharedFiles.find(f => f.id === fileId)
        : files.find(f => f.id === fileId);
      
      if (!file) {
        throw new Error('File not found');
      }

      // Get the filename based on the type
      const filename = isShared 
        ? (file as SharedFileData).filename 
        : (file as FileData).name;

      // For shared files, check if the sender is verified
      if (isShared) {
        const sharedFile = file as SharedFileData;
        const myUsername = storage.getCurrentUser();
        if (!myUsername) {
          throw new Error('No current user found');
        }
        const myKeyBundle = storage.getKeyBundle(myUsername);
        if (!myKeyBundle) {
          throw new Error('Key bundle not found');
        }

        // Check if the sender is verified
        const isSenderVerified = myKeyBundle.recipients?.[sharedFile.shared_by]?.verified;
        if (!isSenderVerified) {
          // Set the unverified sender file info and show dialog
          setUnverifiedSenderFile({
            id: fileId,
            sender: sharedFile.shared_by
          });
          setOpenUnverifiedSender(true);
          setLoading(false);
          return;
        }
      }

      // Step 1: Request challenge
      const challengeResponse = await apiClient.post<ChallengeResponse>('/challenge', {
        username,
        operation: isShared ? 'download_shared_file' : 'download_file'
      });
      if (challengeResponse.status !== 'challenge') {
        throw new Error(challengeResponse.detail || 'Failed to get challenge');
      }

      // Step 2: Sign the appropriate data
      const signature = await signChallenge(
        isShared ? new TextEncoder().encode((file as SharedFileData).share_id.toString()) : new TextEncoder().encode(fileId.toString()),
        secretKey!
      );

      // Step 3: Download file
      const downloadResponse = await apiClient.post<any>(
        isShared ? '/download_shared_file' : '/download_file',
        {
          username,
          ...(isShared ? { share_id: (file as SharedFileData).share_id } : { file_id: fileId }),
          nonce: challengeResponse.nonce,
          signature: btoa(String.fromCharCode.apply(null, Array.from(signature)))
        }
      );

      if (downloadResponse.status !== 'ok') {
        throw new Error(downloadResponse.detail || 'Failed to download file');
      }

      // Step 4: Decrypt file
      const encryptedFile = Uint8Array.from(atob(downloadResponse.encrypted_file), c => c.charCodeAt(0));
      const fileNonce = Uint8Array.from(atob(downloadResponse.file_nonce), c => c.charCodeAt(0));
      
      let decrypted: Uint8Array;
      if (isShared) {
        // For shared files, we need to derive the shared secret using X3DH
        if (!username) {
          throw new Error('Username not found');
        }
        const myKeyBundle = storage.getKeyBundle(username);
        if (!myKeyBundle) {
          throw new Error('Key bundle not found');
        }

        // Get our private OPK that matches the OPK_id from the response, if provided
        let myOPK = undefined;
        if (downloadResponse.opk_id !== undefined) {
          console.log('OPK Debug:', {
            receivedOPKId: downloadResponse.opk_id,
            availableOPKs: myKeyBundle.OPKs_priv?.length,
            keyBundle: {
              hasOPKs: !!myKeyBundle.OPKs_priv,
              OPKCount: myKeyBundle.OPKs_priv?.length,
              OPKIds: myKeyBundle.OPKs_priv?.map((_, i) => i)
            }
          });

          myOPK = myKeyBundle.OPKs_priv?.[downloadResponse.opk_id];
          if (!myOPK) {
            console.log('OPK not found in key bundle, proceeding without OPK');
          }
        } else {
          console.log('No OPK ID provided, proceeding without OPK');
        }

        // Derive the shared secret using our private keys and sender's public keys
        const sharedSecret = await deriveX3DHSharedSecretRecipient({
          senderEKPub: Uint8Array.from(atob(downloadResponse.EK_pub), c => c.charCodeAt(0)),
          senderIKPub: Uint8Array.from(atob(downloadResponse.IK_pub), c => c.charCodeAt(0)),
          senderSPKPub: Uint8Array.from(atob(downloadResponse.SPK_pub), c => c.charCodeAt(0)),
          myIKPriv: Uint8Array.from(atob(myKeyBundle.IK_priv), c => c.charCodeAt(0)),
          mySPKPriv: Uint8Array.from(atob(myKeyBundle.SPK_priv), c => c.charCodeAt(0)),
          myOPKPriv: myOPK ? Uint8Array.from(atob(myOPK), c => c.charCodeAt(0)) : undefined
        });

        console.log('Shared Secret Debug:', {
          hasSharedSecret: !!sharedSecret,
          sharedSecretLength: sharedSecret?.length,
          sharedSecretHex: sharedSecret ? Array.from(sharedSecret).map(b => b.toString(16).padStart(2, '0')).join('') : null
        });

        // Decrypt the file key using the shared secret
        const encryptedFileKey = Uint8Array.from(atob(downloadResponse.encrypted_file_key), c => c.charCodeAt(0));
        const fileKeyNonce = Uint8Array.from(atob(downloadResponse.file_key_nonce), c => c.charCodeAt(0));

        console.log('File Key Debug:', {
          hasEncryptedFileKey: !!encryptedFileKey,
          encryptedFileKeyLength: encryptedFileKey?.length,
          hasFileKeyNonce: !!fileKeyNonce,
          fileKeyNonceLength: fileKeyNonce?.length,
          hasFileNonce: !!fileNonce,
          fileNonceLength: fileNonce?.length
        });

        // Use fileKeyNonce for decrypting the file key
        const fileKey = await decryptFile(encryptedFileKey, sharedSecret, fileKeyNonce);
        console.log('Decrypted File Key Debug:', {
          hasFileKey: !!fileKey,
          fileKeyLength: fileKey?.length
        });

        // Use fileNonce for decrypting the actual file
        decrypted = await decryptFile(encryptedFile, fileKey, fileNonce);
      } else {
        // For regular files, just decrypt the file key with our KEK
        const dek = await decryptFileKey(downloadResponse.encrypted_dek, kek!, downloadResponse.dek_nonce);
        decrypted = await decryptFile(encryptedFile, dek, fileNonce);
      }

      // Step 5: Create a Blob and trigger download
      const blob = new Blob([decrypted], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);

      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
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

  // Add this to Dashboard.tsx temporarily
const TestButton = () => {
  const runTest = async () => {
    try {
      const results = await testX3DHKeyExchange();
      console.log('X3DH Test Results:', results);
    } catch (error) {
      console.error('X3DH Test Failed:', error);
    }
  };

  return (
    <button 
      onClick={runTest}
      style={{ position: 'fixed', bottom: '20px', right: '20px', zIndex: 1000 }}
    >
      Run X3DH Test
    </button>
  );
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
        signature: uint8ArrayToB64(signature)
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
        encrypted_backup: uint8ArrayToB64(encryptedBackup),
        backup_nonce: uint8ArrayToB64(encryptionNonce),
        nonce: backupChallengeResponse.nonce,
        signature: uint8ArrayToB64(backupSignature)
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
        signature: uint8ArrayToB64(signature)
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
        await fetchSharedFiles();
      } catch (error) {
        if (isMounted.current) {
          logDebug('Error in loadFiles', { error });
        }
      }
    };

    loadFiles();

    return () => {
      isMounted.current = false;
      hasFetchedSharedFiles.current = false; // Reset the flag on unmount
      logDebug('Dashboard unmounted', {
        mountCount: mountCount.current
      });
    };
  }, [username, pdk]); // Keep these dependencies for initial load

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
        fileType: file.type,
        hasKEK: !!kek,
        kekLength: kek?.length
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
      logDebug('File key generated', {
        keyLength: fileKey.length
      });

      logDebug('Reading file data');
      const fileData = await file.arrayBuffer();
      logDebug('Encrypting file', {
        fileSize: fileData.byteLength
      });
      const { ciphertext: encryptedFile, nonce: fileNonce } = await encryptWithAESGCM(fileKey, new Uint8Array(fileData));
      logDebug('File encrypted', {
        encryptedSize: encryptedFile.length,
        nonceLength: fileNonce.length
      });

      // Step 3: Encrypt file key with KEK
      logDebug('Encrypting file key with KEK', {
        hasKEK: !!kek,
        kekLength: kek?.length,
        fileKeyLength: fileKey.length
      });
      if (!kek) {
        throw new Error('KEK is not available. Please log out and log back in to refresh your keys.');
      }
      const { ciphertext: encryptedDek, nonce: kekNonce } = await encryptWithAESGCM(kek, fileKey);
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
        encrypted_file: uint8ArrayToB64(encryptedFile),
        file_nonce: uint8ArrayToB64(fileNonce),
        encrypted_dek: uint8ArrayToB64(encryptedDek),
        dek_nonce: uint8ArrayToB64(kekNonce),
        nonce: challengeResponse.nonce,
        signature: uint8ArrayToB64(signature)
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
        responseData: err.response?.data,
        hasKEK: !!kek,
        kekLength: kek?.length
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

      // Step 2: Sign the file ID
      const signature = await signChallenge(
        new TextEncoder().encode(fileId.toString()),
        secretKey!
      );

      // Step 3: Download file
      const downloadResponse = await apiClient.post<any>('/download_file', {
        username,
        file_id: fileId,
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
        const text = new TextDecoder().decode(decrypted);
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
      console.error('Preview error:', err);
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
    // Don't fetch if there's no search query
    if (!userSearchQuery.trim()) {
      setUsers([]);
      return;
    }

    try {
      setLoadingUsers(true);
      setUserError(null);

      // Step 1: Request challenge
      const challengeResponse = await apiClient.post<ChallengeResponse>('/challenge', {
        username,
        operation: 'list_matching_users'
      });

      if (challengeResponse.status !== 'challenge') {
        throw new Error(challengeResponse.detail || 'Failed to get challenge');
      }

      // Step 2: Sign the nonce
      const nonce = Uint8Array.from(atob(challengeResponse.nonce), c => c.charCodeAt(0));
      const signature = await signChallenge(nonce, secretKey!);

      // Step 3: Get matching users
      const listResponse = await apiClient.post<{ status: string; users: UserData[] }>('/list_matching_users', {
        username,
        nonce: challengeResponse.nonce,
        signature: uint8ArrayToB64(signature),
        search_query: userSearchQuery
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

  // Update the useEffect to only trigger when there's a search query
  useEffect(() => {
    if (activeTab === 'users' && username && secretKey && userSearchQuery.trim()) {
      // Add a small delay to prevent too many API calls while typing
      const timeoutId = setTimeout(() => {
        fetchUsers();
      }, 300); // 300ms delay

      return () => clearTimeout(timeoutId);
    } else if (activeTab === 'users' && !userSearchQuery.trim()) {
      // Clear users when search is empty
      setUsers([]);
    }
  }, [activeTab, userSearchQuery]); // Keep userSearchQuery as a dependency

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
      console.log('Starting file share process...');
      const file = files.find(f => f.id === selectedFile);
      if (!file) throw new Error('File not found');
      console.log('Found file:', file.name);

      // 1. Get the DEK for this file
      console.log('Requesting challenge for DEK retrieval...');
      const challengeResponse = await apiClient.post<ChallengeResponse>('/challenge', {
        username,
        operation: 'retrieve_file_dek'
      });

      if (challengeResponse.status !== 'challenge') {
        throw new Error(challengeResponse.detail || 'Failed to get challenge');
      }
      console.log('Got challenge for DEK retrieval');

      // Sign the nonce 
      const signature = await signChallenge(b64ToUint8Array(challengeResponse.nonce), secretKey!);
      console.log('Signed DEK challenge');

      // Get the encrypted DEK
      console.log('Retrieving encrypted DEK...');
      const dekResponse = await apiClient.post<{ status: string; encrypted_dek: string; dek_nonce: string }>('/retrieve_file_dek', {
        username,
        file_id: selectedFile,
        nonce: challengeResponse.nonce,
        signature: uint8ArrayToB64(signature)
      });

      if (dekResponse.status !== 'ok') {
        throw new Error('Failed to retrieve file key');
      }
      console.log('Retrieved encrypted DEK:', {
        encrypted_dek_length: dekResponse.encrypted_dek.length,
        dek_nonce_length: dekResponse.dek_nonce.length
      });

      console.log('Retrieved encrypted DEK');

      // Decrypt the file key using the KEK from our keyBundle
      const fileKey = await decryptFileKey(dekResponse.encrypted_dek, kek!, dekResponse.dek_nonce);
      console.log('Decrypted file key');
      
      for (const recipientUsername of selectedRecipients) {
        console.log(`Processing recipient: ${recipientUsername}`);
        
        if(test_empty_opk_share){
        // Clear recipient's OPKs first (for testing)
        console.log('Clearing recipient OPKs...');
        const clearOPKsChallengeResponse = await apiClient.post<ChallengeResponse>('/challenge', {
          username,
          operation: 'clear_user_opks'
        });

        if (clearOPKsChallengeResponse.status !== 'challenge') {
          throw new Error('Failed to get challenge for clearing OPKs');
        }

        const clearOPKsSignature = await signChallenge(b64ToUint8Array(clearOPKsChallengeResponse.nonce), secretKey!);
        await apiClient.post('/clear_user_opks', {
          username,
          target_username: recipientUsername,
          nonce: clearOPKsChallengeResponse.nonce,
          signature: uint8ArrayToB64(clearOPKsSignature)
        });
        console.log('Cleared recipient OPKs');
      }
        // 2. Get recipient's verified pre-key bundle from local storage
        const myUsername = storage.getCurrentUser();
        if (!myUsername) throw new Error('No current user found');
        const myKeyBundle = storage.getKeyBundle(myUsername);
        if (!myKeyBundle) throw new Error('Key bundle not found for current user');
        const storedRecipientBundle = myKeyBundle.recipients?.[recipientUsername]?.data;
        if (!storedRecipientBundle) throw new Error('Recipient bundle not found or not verified');
        console.log('Retrieved stored recipient bundle');

        // 3. Get fresh key bundle from server for TOFU check
        console.log('Requesting fresh key bundle...');
        const bundleChallengeResponse = await apiClient.post<ChallengeResponse>('/challenge', {
          username: myUsername,
          operation: 'get_pre_key_bundle'
        });

        if (bundleChallengeResponse.status !== 'challenge') {
          throw new Error('Failed to get challenge for key bundle');
        }
        console.log('Got challenge for key bundle');

        const bundleSignature = await signChallenge(b64ToUint8Array(bundleChallengeResponse.nonce), secretKey!);
        const freshBundleResponse = await apiClient.post<{ status: string; prekey_bundle: any }>('/get_pre_key_bundle', {
          username: myUsername,
          target_username: recipientUsername,
          nonce: bundleChallengeResponse.nonce,
          signature: uint8ArrayToB64(bundleSignature)
        });

        if (freshBundleResponse.status !== 'ok') {
          throw new Error('Failed to get fresh key bundle');
        }
        console.log('Retrieved fresh key bundle');

        // 4. Compare stored bundle with fresh bundle for TOFU
        const freshBundle = freshBundleResponse.prekey_bundle;
        if (freshBundle.IK_pub !== storedRecipientBundle.IK_pub ||
            freshBundle.SPK_pub !== storedRecipientBundle.SPK_pub ||
            freshBundle.SPK_signature !== storedRecipientBundle.SPK_signature) {
          throw new Error('Key bundle mismatch - possible security issue');
        }
        console.log('TOFU check passed');

        // 5. Get OPK for recipient
        console.log('Requesting OPK...');
        const opkChallengeResponse = await apiClient.post<ChallengeResponse>('/challenge', {
          username: myUsername,
          operation: 'get_opk'
        });

        if (opkChallengeResponse.status !== 'challenge') {
          throw new Error('Failed to get challenge for OPK');
        }
        console.log('Got challenge for OPK');

        const opkSignature = await signChallenge(b64ToUint8Array(opkChallengeResponse.nonce), secretKey!);
        let opkResponse = null;
        try {
          const response = await apiClient.post<{ opk_id: number; pre_key: string }>('/opk', {
            username: myUsername,
            target_username: recipientUsername,
            nonce: opkChallengeResponse.nonce,
            signature: uint8ArrayToB64(opkSignature)
          });
          opkResponse = response;
          console.log('Retrieved OPK:', { opk_id: opkResponse.opk_id });
        } catch (err: any) {
          // Check for both 404 and "No OPK available" message
          if (err.response?.status === 404 || err.message === 'No OPK available' || err.response?.data?.detail === 'No OPK available') {
            console.log('No OPK available, proceeding without OPK');
            // Continue execution with opkResponse as null
          } else {
            console.error('Error getting OPK:', err);
            throw err;
          }
        }

        // 6. Generate ephemeral X25519 key pair
        console.log('Generating ephemeral key pair...');
        const ephemeralKeyPair = await generateEphemeralKeyPair();
        console.log('Generated ephemeral key pair');

        // 7. Derive X3DH shared secret
        console.log('Deriving X3DH shared secret...');
        console.log('Key data:', {
          myIKPriv: b64ToUint8Array(myKeyBundle.IK_priv).length,
          myEKPriv: ephemeralKeyPair.privateKey.length,
          recipientIKPub: b64ToUint8Array(freshBundle.IK_pub).length,
          recipientSPKPub: b64ToUint8Array(freshBundle.SPK_pub).length,
          hasOPK: !!opkResponse
        });

        const sharedSecret = await deriveX3DHSharedSecret({
          myIKPriv: b64ToUint8Array(myKeyBundle.IK_priv),
          myEKPriv: ephemeralKeyPair.privateKey,
          recipientIKPub: b64ToUint8Array(freshBundle.IK_pub),
          recipientSPKPub: b64ToUint8Array(freshBundle.SPK_pub),
          recipientSPKSignature: b64ToUint8Array(freshBundle.SPK_signature),
          recipientOPKPub: opkResponse ? b64ToUint8Array(opkResponse.pre_key) : undefined
        });
        console.log('Derived shared secret');

        // 8. Encrypt the file key (DEK) with the shared secret
        console.log('Encrypting file key with shared secret...');
        const { ciphertext, nonce } = await encryptWithAESGCM(sharedSecret, fileKey);
        console.log('Encrypted file key:', {
          ciphertext_length: ciphertext.length,
          nonce_length: nonce.length
        });

        // 9. Request challenge for share_file
        console.log('Requesting challenge for share_file...');
        const shareChallengeResponse = await apiClient.post<{ status: string; nonce: string; detail?: string }>('/challenge', {
          username,
          operation: 'share_file'
        });

        if (shareChallengeResponse.status !== 'challenge') {
          throw new Error('Failed to get challenge for sharing');
        }
        console.log('Got challenge for share_file');

        // 10. Sign the encrypted file key
        if (!secretKey) throw new Error('Secret key not available');
        const shareSignature = await signChallenge(ciphertext, secretKey);
        console.log('Signed share request');

        // 11. Send /share_file request
        console.log('Sending share_file request...');
        await apiClient.post('/share_file', {
          username,
          file_id: selectedFile,
          recipient_username: recipientUsername,
          EK_pub: uint8ArrayToB64(ephemeralKeyPair.publicKey),
          IK_pub: myKeyBundle.IK_pub,
          encrypted_file_key: uint8ArrayToB64(ciphertext),
          file_key_nonce: uint8ArrayToB64(nonce),
          SPK_pub: myKeyBundle.SPK_pub,
          SPK_signature: myKeyBundle.SPK_signature,
          ...(opkResponse && {
            OPK_ID: opkResponse.opk_id,
            pre_key: opkResponse.pre_key
          }),
          nonce: shareChallengeResponse.nonce,
          signature: uint8ArrayToB64(shareSignature)
        });
        console.log('Share request sent successfully');
      }

      console.log('Share process completed successfully');
      setOpenShare(false);
      setSelectedRecipients([]);

    } catch (err: any) {
      console.error('Share process failed:', err);
      setError(err.message || 'Failed to share file');
    } finally {
      setLoading(false);
    }
  };

  // Add this function to fetch shared files
  const fetchSharedFiles = async () => {
    if (!username || !secretKey || hasFetchedSharedFiles.current) return;
    
    try {
      setLoadingSharedFiles(true);
      setError(null);

      // Request challenge
      const challengeResponse = await apiClient.post<ChallengeResponse>('/challenge', {
        username,
        operation: 'list_shared_files'
      });

      if (challengeResponse.status !== 'challenge') {
        throw new Error(challengeResponse.detail || 'Failed to get challenge');
      }

      // Sign the nonce
      const nonce = Uint8Array.from(atob(challengeResponse.nonce), c => c.charCodeAt(0));
      const signature = await signChallenge(nonce, secretKey);

      // Get shared files
      const response = await apiClient.post<{ status: string; files: SharedFileData[] }>('/list_shared_files', {
        username,
        nonce: challengeResponse.nonce,
        signature: uint8ArrayToB64(signature)
      });

      if (response.status === 'ok') {
        setSharedFiles(response.files);
        hasFetchedSharedFiles.current = true;
      } else {
        throw new Error('Failed to list shared files');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to fetch shared files');
    } finally {
      setLoadingSharedFiles(false);
    }
  };

  // Update the useEffect
  useEffect(() => {
    if (activeTab === 'files' && username && secretKey) {
      if (!hasFetchedFiles.current) {
        fetchFiles();
      }
      if (!hasFetchedSharedFiles.current) {
        fetchSharedFiles();
      }
    }
  }, [activeTab]); // Only depend on activeTab

  // Add a refresh function for shared files
  const refreshSharedFiles = async () => {
    hasFetchedSharedFiles.current = false;
    await fetchSharedFiles();
  };

  return (
    <>
      <MatrixBackground />
      <TestButton />
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
              <ListItem
                button
                onClick={() => {
                  const currentUser = storage.getCurrentUser();
                  if (currentUser) {
                    storage.removeKeyBundle(currentUser);
                  }
                  storage.clearStorage();
                  navigate('/login');
                }}
              >
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
                              <IconButton onClick={() => handleDownload(file.id, false)} sx={{ color: '#00ff00' }}>
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
                      onClick={refreshSharedFiles} 
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
                                <IconButton onClick={() => handleDownload(file.id, true)} sx={{ color: '#00ff00' }}>
                                  <DownloadIcon />
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
              </>
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
          if (!loading) {
            setOpenShare(false);
            setSelectedRecipients([]);
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
                      Encrypting and sharing file...
                    </Typography>
                  </Box>
                )}
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
            disabled={loading}
          >
            Cancel
          </Button>
          <CyberButton
            onClick={handleShareConfirm}
            size="small"
            sx={{ minWidth: 100, fontSize: '0.95rem', height: 36, px: 2.5, py: 1 }}
            disabled={selectedRecipients.length === 0 || loading}
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

      {/* No OPK Confirmation Dialog */}
      <Dialog
        open={openNoOPKConfirm}
        onClose={() => {
          setOpenNoOPKConfirm(false);
          setPendingShare(null);
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
          Share Without One-Time Keys
        </DialogTitle>
        <DialogContent sx={{ mt: 2 }}>
          <Typography sx={{ color: '#00ff00', mb: 2 }}>
            {pendingShare?.recipient} has no available one-time keys. While you can still share the file, this is less secure than using one-time keys.
          </Typography>
          <Typography sx={{ color: 'rgba(0, 255, 0, 0.7)', fontSize: '0.9rem' }}>
            Would you like to proceed with sharing anyway?
          </Typography>
        </DialogContent>
        <DialogActions sx={{ borderTop: '1px solid rgba(0, 255, 0, 0.2)', p: 2 }}>
          <Button 
            onClick={() => {
              setOpenNoOPKConfirm(false);
              setPendingShare(null);
            }}
            sx={{ color: 'rgba(0, 255, 0, 0.7)' }}
          >
            Cancel
          </Button>
          <CyberButton
            onClick={async () => {
              if (!pendingShare) return;
              try {
                const { recipient, fileKey, freshBundle } = pendingShare;
                const myUsername = storage.getCurrentUser();
                if (!myUsername) throw new Error('No current user found');
                const myKeyBundle = storage.getKeyBundle(myUsername);
                if (!myKeyBundle) throw new Error('Key bundle not found for current user');

                // Generate ephemeral key pair
                console.log('Generating ephemeral key pair...');
                const ephemeralKeyPair = await generateEphemeralKeyPair();
                console.log('Generated ephemeral key pair');

                // Derive X3DH shared secret without OPK
                console.log('Deriving X3DH shared secret without OPK...');
                const sharedSecret = await deriveX3DHSharedSecret({
                  myIKPriv: b64ToUint8Array(myKeyBundle.IK_priv),
                  myEKPriv: ephemeralKeyPair.privateKey,
                  recipientIKPub: b64ToUint8Array(freshBundle.IK_pub),
                  recipientSPKPub: b64ToUint8Array(freshBundle.SPK_pub),
                  recipientSPKSignature: b64ToUint8Array(freshBundle.SPK_signature)
                });
                console.log('Derived shared secret without OPK');

                // Encrypt the file key with the shared secret
                console.log('Encrypting file key with shared secret...');
                const { ciphertext, nonce } = await encryptWithAESGCM(sharedSecret, fileKey);

                // Request challenge for share_file
                const shareChallengeResponse = await apiClient.post<{ status: string; nonce: string; detail?: string }>('/challenge', {
                  username,
                  operation: 'share_file'
                });

                if (shareChallengeResponse.status !== 'challenge') {
                  throw new Error('Failed to get challenge for sharing');
                }

                // Sign the encrypted file key
                if (!secretKey) throw new Error('Secret key not available');
                const shareSignature = await signChallenge(ciphertext, secretKey);

                // Send share_file request without OPK
                await apiClient.post('/share_file', {
                  username,
                  file_id: selectedFile,
                  recipient_username: recipient,
                  EK_pub: uint8ArrayToB64(ephemeralKeyPair.publicKey),
                  IK_pub: myKeyBundle.IK_pub,
                  encrypted_file_key: uint8ArrayToB64(ciphertext),
                  file_key_nonce: uint8ArrayToB64(nonce),
                  SPK_pub: myKeyBundle.SPK_pub,
                  SPK_signature: myKeyBundle.SPK_signature,
                  nonce: shareChallengeResponse.nonce,
                  signature: uint8ArrayToB64(shareSignature)
                });

                console.log('Share request sent successfully without OPK');
                setOpenNoOPKConfirm(false);
                setPendingShare(null);
                setOpenShare(false);
                setSelectedRecipients([]);
              } catch (err: any) {
                console.error('Share process failed:', err);
                setError(err.message || 'Failed to share file');
              }
            }}
          >
            Share Anyway
          </CyberButton>
        </DialogActions>
      </Dialog>

      {/* Unverified Sender Dialog */}
      <Dialog
        open={openUnverifiedSender}
        onClose={() => {
          setOpenUnverifiedSender(false);
          setUnverifiedSenderFile(null);
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
          Unverified Sender
        </DialogTitle>
        <DialogContent sx={{ mt: 2 }}>
          <Typography sx={{ color: '#00ff00', mb: 2 }}>
            The file you are trying to download was shared by {unverifiedSenderFile?.sender}, who is not a verified user.
          </Typography>
          <Typography sx={{ color: 'rgba(0, 255, 0, 0.7)', fontSize: '0.9rem', mb: 2 }}>
            While you can still download the file, it is recommended to verify the sender first to ensure the file's authenticity and security.
          </Typography>
          <Typography sx={{ color: 'rgba(255, 0, 0, 0.7)', fontSize: '0.9rem' }}>
            Would you like to proceed with downloading anyway?
          </Typography>
        </DialogContent>
        <DialogActions sx={{ 
          borderTop: '1px solid rgba(0, 255, 0, 0.2)', 
          p: 2,
          display: 'flex',
          justifyContent: 'space-between'
        }}>
          <Button 
            onClick={() => {
              setOpenUnverifiedSender(false);
              setUnverifiedSenderFile(null);
            }}
            sx={{ 
              color: 'rgba(0, 255, 0, 0.7)',
              mr: 'auto'
            }}
          >
            Cancel
          </Button>
          <CyberButton
            onClick={async () => {
              if (!unverifiedSenderFile) return;
              setOpenUnverifiedSender(false);
              setUnverifiedSenderFile(null);
              await handleDownload(unverifiedSenderFile.id, true);
            }}
            sx={{
              minWidth: 120,
              fontSize: '0.9rem',
              height: 32,
              px: 2,
              py: 0.5,
              backgroundColor: 'rgba(255, 0, 0, 0.2)',
              '&:hover': {
                backgroundColor: 'rgba(255, 0, 0, 0.3)'
              }
            }}
          >
            Download Anyway
          </CyberButton>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default Dashboard;