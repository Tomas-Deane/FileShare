const { createProxyMiddleware } = require('http-proxy-middleware');

module.exports = function(app) {
  app.use(
    '/api',
    createProxyMiddleware({
      target: 'https://nrmc.gobbler.info',
      changeOrigin: true,
      secure: false, // This allows self-signed certificates
      proxyTimeout: 30000, // Increase timeout to 30 seconds
      timeout: 30000,
      pathRewrite: {
        '^/api': '', // Remove the /api prefix when forwarding to the server
      },
      onProxyReq: function(proxyReq, req, res) {
        // Log the outgoing request
        console.log('Proxy request:', {
          method: req.method,
          url: req.url,
          target: 'https://nrmc.gobbler.info',
          headers: proxyReq.getHeaders(),
          body: req.body
        });

        // Ensure the request body is properly forwarded
        if (req.body) {
          const bodyData = JSON.stringify(req.body);
          proxyReq.setHeader('Content-Type', 'application/json');
          proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
          proxyReq.write(bodyData);
        }
      },
      onProxyRes: function(proxyRes, req, res) {
        // Add CORS headers
        proxyRes.headers['Access-Control-Allow-Origin'] = '*';
        proxyRes.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS';
        proxyRes.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization';
        
        // Log proxy response for debugging
        console.log('Proxy response:', {
          statusCode: proxyRes.statusCode,
          headers: proxyRes.headers,
          url: req.url
        });

        // Log the response body
        let responseBody = '';
        proxyRes.on('data', function(chunk) {
          responseBody += chunk;
        });
        proxyRes.on('end', function() {
          console.log('Proxy response body:', responseBody);
        });
      },
      onError: function(err, req, res) {
        console.error('Proxy error details:', {
          error: err.message,
          code: err.code,
          url: req.url,
          method: req.method,
          stack: err.stack,
          host: req.headers.host,
          target: 'https://nrmc.gobbler.info'
        });
        
        // Send a more detailed error response
        res.writeHead(500, {
          'Content-Type': 'application/json',
        });
        res.end(JSON.stringify({
          error: 'Proxy error',
          message: err.message,
          code: err.code,
          details: 'Unable to connect to the API server. Please ensure the server is running and accessible.'
        }));
      }
    })
  );
}; 