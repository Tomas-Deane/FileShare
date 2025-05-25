import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { apiClient } from '../utils/apiClient';

interface ProtectedRouteProps {
  children: React.ReactNode;
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children }) => {
  const location = useLocation();
  const [isAuthenticated, setIsAuthenticated] = React.useState<boolean | null>(null);

  React.useEffect(() => {
    const checkAuth = async () => {
      try {
        // Try to make an authenticated request
        await apiClient.get('/auth/check');
        setIsAuthenticated(true);
      } catch (error) {
        setIsAuthenticated(false);
      }
    };

    checkAuth();
  }, []);

  // Show loading state while checking authentication
  if (isAuthenticated === null) {
    return (
      <div style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '100vh',
        background: 'rgba(0,0,0,0.8)',
        color: '#00ff00'
      }}>
        Verifying authentication...
      </div>
    );
  }

  // Redirect to login if not authenticated
  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Render children if authenticated
  return <>{children}</>;
};

export default ProtectedRoute; 