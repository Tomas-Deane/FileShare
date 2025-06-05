export const securityConfig = {
  // Enforce HTTPS for all API calls
  apiBaseUrl: 'https://nrmc.gobbler.info:443',
  
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
  cors: {
    allowedOrigins: ['https://nrmc.gobbler.info:443'],
    allowedMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    allowCredentials: true,
  },
}; 