// fileshareweb/src/contexts/AuthContext.tsx
import React, { createContext, useContext, useState } from 'react';
import { KeyObject } from 'crypto';

interface AuthContextType {
  username: string;
  secretKey: Uint8Array | null;
  pdk: KeyObject | null;
  kek: Uint8Array | null;
  setAuthData: (data: {
    username: string;
    secretKey: Uint8Array;
    pdk: KeyObject;
    kek: Uint8Array;
  }) => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [username, setUsername] = useState('');
  const [secretKey, setSecretKey] = useState<Uint8Array | null>(null);
  const [pdk, setPdk] = useState<KeyObject | null>(null);
  const [kek, setKek] = useState<Uint8Array | null>(null);

  const setAuthData = (data: {
    username: string;
    secretKey: Uint8Array;
    pdk: KeyObject;
    kek: Uint8Array;
  }) => {
    setUsername(data.username);
    setSecretKey(data.secretKey);
    setPdk(data.pdk);
    setKek(data.kek);
  };

  return (
    <AuthContext.Provider value={{ username, secretKey, pdk, kek, setAuthData }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};