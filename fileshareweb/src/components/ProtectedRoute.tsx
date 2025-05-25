import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';

interface ProtectedRouteProps {
  children: React.ReactNode;
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children }) => {
  const location = useLocation();
  
  // Simply check for the session cookie
  const hasSessionCookie = document.cookie.includes('session_token=');
  
  if (!hasSessionCookie) {
    console.log('No session cookie found, redirecting to login');
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // If we have a session cookie, render the protected content
  return <>{children}</>;
};

export default ProtectedRoute; 