export const securityConfig = {
  // Enforce HTTPS for all API calls
  apiBaseUrl: process.env.REACT_APP_API_URL?.replace('http://', 'https://') || 'https://localhost:3001',
  
  // Security headers configuration
  headers: {
    'Content-Security-Policy': "default-src 'self'; connect-src 'self' https:; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}';",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  },

  // Cookie security settings
  cookieOptions: {
    secure: true,
    httpOnly: true,
    sameSite: 'strict' as const,
  },

  // CORS configuration
  corsOptions: {
    origin: process.env.NODE_ENV === 'production' 
      ? process.env.REACT_APP_ALLOWED_ORIGINS?.split(',') 
      : ['https://localhost:3000'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  },
}; 