import React, { useState } from 'react';
import { generateFileKey, encryptFile, encryptWithPublicKey } from '../utils/crypto';

const Dashboard: React.FC = () => {
  const [message, setMessage] = useState<string>('');

  const handleFileShare = async (file: File, recipient: string) => {
    try {
      // Generate a new file key
      const fileKey = await generateFileKey();
      
      // Read file as ArrayBuffer
      const arrayBuffer = await file.arrayBuffer();
      const fileData = new Uint8Array(arrayBuffer);
      
      // Encrypt the file
      const { encrypted: encryptedFile, nonce: fileNonce } = await encryptFile(fileData, fileKey);
      
      // Encrypt the file key with the recipient's public key
      const { encrypted: encryptedFileKey, nonce: keyNonce } = await encryptWithPublicKey(
        fileKey,
        recipient
      );
      
      // Create the file share request
      const request = {
        filename: file.name,
        recipient: recipient,
        encrypted_file: btoa(String.fromCharCode(...Array.from(encryptedFile))),
        file_nonce: btoa(String.fromCharCode(...Array.from(fileNonce))),
        encrypted_file_key: btoa(String.fromCharCode(...Array.from(encryptedFileKey))),
        key_nonce: btoa(String.fromCharCode(...Array.from(keyNonce)))
      };
      
      // Send the request
      const response = await fetch('/api/share', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(request),
      });
      
      if (!response.ok) {
        throw new Error('Failed to share file');
      }
      
      // Show success message
      setMessage('File shared successfully');
    } catch (error) {
      console.error('Error sharing file:', error);
      setMessage('Failed to share file: ' + (error instanceof Error ? error.message : String(error)));
    }
  };

  return (
    <div>
      {/* Render your component content here */}
    </div>
  );
};

export default Dashboard; 