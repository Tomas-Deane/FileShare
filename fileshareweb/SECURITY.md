# Security Documentation

This document is for you my lovee naemm <3 it outlines the security features implemented in the FileShare web application and how to use them properly as this is a different dev process due to the added security features required by SSL and CA to run a https secure webapp.

## Table of Contents
- [Security Features](#security-features)
- [Using the Secure API Client](#using-the-secure-api-client)
- [Development Setup](#development-setup)
- [Security Headers](#security-headers)
- [Cookie Security](#cookie-security)
- [CORS Configuration](#cors-configuration)
- [Best Practices](#best-practices)

## Security Features

The application implements several security measures:

- HTTPS enforcement for all connections
- Secure headers (HSTS, CSP, XSS Protection)
- Secure cookie handling
- CORS protection
- Automatic HTTPS redirection
- Security header verification

## Using the Secure API Client

The `apiClient` is a secure wrapper around axios that enforces security best practices. Always use `apiClient` instead of direct axios calls.

### Basic Usage

```typescript
import { apiClient } from '../utils/apiClient';

// GET request
const fetchData = async () => {
  try {
    const response = await apiClient.get('/api/data');
    return response.data;
  } catch (error) {
    if (error.response?.status === 401) {
      // Handle unauthorized access
    }
    console.error('Error:', error);
  }
};

// POST request
const postData = async (data) => {
  try {
    const response = await apiClient.post('/api/data', data);
    return response.data;
  } catch (error) {
    if (error.response?.status === 401) {
      // Handle unauthorized access
    }
    console.error('Error:', error);
  }
};
```

### Available Methods

- `apiClient.get(url, config?)`
- `apiClient.post(url, data, config?)`
- `apiClient.put(url, data, config?)`
- `apiClient.delete(url, config?)`

## Development Setup

1. Generate SSL certificates:
```bash
npm run setup-ssl
```

2. Start the development server:
```bash
npm start
```

3. Accept the self-signed certificate warning in your browser

## Security Headers

The application implements the following security headers:

- `Content-Security-Policy`: Restricts resource loading
- `Strict-Transport-Security`: Forces HTTPS
- `X-Frame-Options`: Prevents clickjacking
- `X-XSS-Protection`: XSS protection
- `X-Content-Type-Options`: Prevents MIME type sniffing

## Cookie Security

Cookies are configured with the following security options:

- `secure: true`: Only sent over HTTPS
- `httpOnly: true`: Not accessible via JavaScript
- `sameSite: 'strict'`: Prevents CSRF attacks

## CORS Configuration

CORS is configured with strict rules:

```typescript
{
  origin: process.env.NODE_ENV === 'production' 
    ? process.env.REACT_APP_ALLOWED_ORIGINS?.split(',') 
    : ['https://localhost:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}
```

## Best Practices

1. **Always use apiClient**
```typescript
// ❌ Don't use direct axios
axios.get('/api/data');

// ✅ Use apiClient instead
apiClient.get('/api/data');
```

2. **Handle 401 responses**
```typescript
try {
  await apiClient.get('/api/protected-data');
} catch (error) {
  if (error.response?.status === 401) {
    // Handle unauthorized access
    // Redirect to login or refresh token
  }
}
```

3. **External Resources**
When adding external resources, update the CSP in `security.ts`:
```typescript
headers: {
  'Content-Security-Policy': "default-src 'self'; connect-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';",
}
```

4. **Environment Variables**
Create a `.env` file with:
```
REACT_APP_API_URL=https://localhost:3001
REACT_APP_ALLOWED_ORIGINS=https://localhost:3000
SSL_CRT_FILE=./ssl/cert.pem
SSL_KEY_FILE=./ssl/key.pem
```

5. **Testing Security**
- Test with HTTPS enabled
- Verify security headers
- Test CORS with different origins
- Verify cookie security settings

## Security Checklist

Before deploying:
- [ ] All API calls use `apiClient`
- [ ] SSL certificates are properly configured
- [ ] Security headers are present
- [ ] CORS is properly configured
- [ ] Cookie security settings are enabled
- [ ] Environment variables are set
- [ ] No sensitive data in client-side code
- [ ] All external resources are allowed in CSP
- [ ] Error handling for 401 responses
- [ ] HTTPS is enforced everywhere

## Troubleshooting

1. **Certificate Warnings**
   - Accept the self-signed certificate in development
   - Use proper SSL certificates in production

2. **CORS Errors**
   - Check `REACT_APP_ALLOWED_ORIGINS`
   - Verify backend CORS configuration
   - Ensure credentials are properly handled

3. **Security Header Issues**
   - Check browser console for CSP violations
   - Verify all required headers are present
   - Update CSP if adding new external resources

4. **Cookie Issues**
   - Ensure cookies are sent over HTTPS
   - Check cookie security flags
   - Verify sameSite policy

## Additional Resources

- [MDN Web Security](https://developer.mozilla.org/en-US/docs/Web/Security)
- [OWASP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/React_Security_Cheat_Sheet.html)
- [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [HTTP Strict Transport Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security) 