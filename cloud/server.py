#!/usr/bin/env python3
import os
import base64
import secrets
import logging

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

import models

# Logging setup
LOG_FILE = os.path.join(os.path.dirname(__file__), 'server_debug.log')
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s: %(message)s'
)

# Initialize database tables
models.init_db()
db = models.UserDB()

app = FastAPI(title="FileShare API")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://localhost:3000", "https://gobbler.info"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class SignupRequest(BaseModel):
    username: str
    salt: str
    argon2_opslimit: int
    argon2_memlimit: int
    public_key: str
    encrypted_privkey: str
    privkey_nonce: str


class LoginRequest(BaseModel):
    username: str


class AuthenticateRequest(BaseModel):
    username: str
    signature: str


@app.post("/signup")
def signup(req: SignupRequest):
    logging.debug(f"SignupRequest body: {req.json()}")
    logging.info(f"Signup attempt for '{req.username}'")

    if db.get_user(req.username):
        logging.warning(f"User '{req.username}' already exists")
        raise HTTPException(status_code=400, detail="User already exists")

    db.add_user(
        req.username,
        base64.b64decode(req.salt),
        req.argon2_opslimit,
        req.argon2_memlimit,
        base64.b64decode(req.public_key),
        base64.b64decode(req.encrypted_privkey),
        base64.b64decode(req.privkey_nonce)
    )
    resp = {"status": "ok"}
    logging.info(f"Signup successful for '{req.username}'")
    logging.debug(f"Signup response: {resp}")
    return resp


@app.post("/login")
def login(req: LoginRequest):
    logging.debug(f"LoginRequest body: {req.json()}")
    logging.info(f"Login request for '{req.username}'")

    user = db.get_user(req.username)
    if not user:
        logging.warning(f"Unknown user '{req.username}'")
        raise HTTPException(status_code=404, detail="Unknown user")

    challenge = secrets.token_bytes(32)
    db.add_challenge(req.username, challenge)
    logging.debug(f"Stored challenge for '{req.username}': {challenge.hex()}")

    resp = {
        "status": "challenge",
        "nonce": base64.b64encode(challenge).decode(),
        "salt": base64.b64encode(user['salt']).decode(),
        "argon2_opslimit": user['argon2_opslimit'],
        "argon2_memlimit": user['argon2_memlimit'],
        "encrypted_privkey": base64.b64encode(user['encrypted_privkey']).decode(),
        "privkey_nonce": base64.b64encode(user['privkey_nonce']).decode()
    }
    logging.debug(f"Login response: {resp}")
    return resp


@app.post("/authenticate")
def authenticate(req: AuthenticateRequest, response: Response):
    logging.debug(f"AuthenticateRequest body: {req.json()}")
    logging.info(f"Authenticate attempt for '{req.username}'")

    user = db.get_user(req.username)
    if not user:
        logging.warning(f"Unknown user '{req.username}' at authenticate")
        raise HTTPException(status_code=404, detail="Unknown user")

    challenge = db.get_pending_challenge(req.username)
    if challenge is None:
        logging.warning(f"No valid pending challenge for '{req.username}'")
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    signature = base64.b64decode(req.signature)
    pubkey = user['public_key']
    logging.debug(f"Verifying signature: challenge={challenge.hex()}, signature={signature.hex()}, pubkey={pubkey.hex()}")

    try:
        # Convert raw public key bytes to ECDSA public key
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            pubkey
        )
        
        # Verify the signature
        public_key.verify(
            signature,
            challenge,
            ec.ECDSA(hashes.SHA256())
        )
        
        logging.info(f"Signature valid for '{req.username}'")
        db.delete_challenge(req.username)
        
        # Create a simple session token (in production, use a proper JWT)
        session_token = secrets.token_urlsafe(32)
        
        # Set session cookie
        response.set_cookie(
            key="session_token",
            value=session_token,
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=86400  # 24 hours
        )
        
        resp = {"status": "ok", "message": "login successful"}
        logging.debug(f"Authenticate response: {resp}")
        return resp
    except InvalidSignature:
        logging.warning(f"Bad signature for '{req.username}'")
        db.delete_challenge(req.username)
        raise HTTPException(status_code=401, detail="Bad signature")
    except Exception as e:
        logging.error(f"Error verifying signature: {str(e)}")
        db.delete_challenge(req.username)
        raise HTTPException(status_code=500, detail="Error verifying signature")


if __name__ == "__main__":
    import uvicorn

    # Host/port configuration
    host = os.environ.get('FS_HOST', '0.0.0.0')
    port = int(os.environ.get('FS_HTTPS_PORT', '3210'))
    certfile = os.environ.get('SSL_CERTFILE', 'cert.pem')
    keyfile = os.environ.get('SSL_KEYFILE', 'key.pem')

    if not (os.path.exists(certfile) and os.path.exists(keyfile)):
        logging.error(f"Missing cert or key: '{certfile}' / '{keyfile}'")
        raise SystemExit("TLS cert/key not found; please generate them via OpenSSL")

    logging.info(f"Starting HTTPS server on {host}:{port}")
    uvicorn.run(
        "server:app",
        host=host,
        port=port,
        ssl_certfile=certfile,
        ssl_keyfile=keyfile,
        log_config=None
    )

