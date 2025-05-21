const fs = require('fs');
const path = require('path');

const SSL_KEY_PATH = path.join(__dirname, 'ssl', 'key.pem');
const SSL_CERT_PATH = path.join(__dirname, 'ssl', 'cert.pem');

module.exports = {
  key: fs.readFileSync(SSL_KEY_PATH),
  cert: fs.readFileSync(SSL_CERT_PATH),
}; 