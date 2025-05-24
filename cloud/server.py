#!/usr/bin/env python3
import os
import logging

from fastapi import FastAPI
from pydantic import BaseModel

import models
import handlers

# Logging setup
LOG_FILE = os.path.join(os.path.dirname(__file__), 'server_debug.log')
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s: %(message)s'
)

# Initialize DB
models.init_db()
db = models.UserDB()

app = FastAPI(title="FileShare API")


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


class ChallengeRequest(BaseModel):
    username: str
    operation: str  # e.g. "login", "change_username", "change_password"


class AuthenticateRequest(BaseModel):
    username: str
    nonce: str
    signature: str


class ChangeUsernameRequest(BaseModel):
    username: str
    new_username: str
    nonce: str
    signature: str


class ChangePasswordRequest(BaseModel):
    username: str
    salt: str
    argon2_opslimit: int
    argon2_memlimit: int
    encrypted_privkey: str
    privkey_nonce: str
    nonce: str
    signature: str


@app.post("/signup")
def signup(req: SignupRequest):
    logging.debug(f"SignupRequest body: {req.json()}")
    resp = handlers.signup_handler(req, db)
    logging.debug(f"Signup response: {resp}")
    return resp


@app.post("/challenge")
def challenge(req: ChallengeRequest):
    logging.debug(f"ChallengeRequest body: {req.json()}")
    resp = handlers.challenge_handler(req, db)
    logging.debug(f"Challenge response: {resp}")
    return resp


@app.post("/login")
def login(req: LoginRequest):
    logging.debug(f"LoginRequest body: {req.json()}")
    # internally fetch a nonce via the single challenge endpoint logic
    challenge_req = ChallengeRequest(username=req.username, operation="login")
    chal = handlers.challenge_handler(challenge_req, db)
    # now tack on the extra user‐specific fields
    full = handlers.login_handler_continue(req, db, chal["nonce"])
    logging.debug(f"Login response: {full}")
    return full


@app.post("/authenticate")
def authenticate(req: AuthenticateRequest):
    logging.debug(f"AuthenticateRequest body: {req.json()}")
    resp = handlers.authenticate_handler(req, db)
    logging.debug(f"Authenticate response: {resp}")
    return resp


@app.post("/change_username")
def change_username(req: ChangeUsernameRequest):
    logging.debug(f"ChangeUsernameRequest body: {req.json()}")
    resp = handlers.change_username_handler(req, db)
    logging.debug(f"ChangeUsername response: {resp}")
    return resp


@app.post("/change_password")
def change_password(req: ChangePasswordRequest):
    logging.debug(f"ChangePasswordRequest body: {req.json()}")
    resp = handlers.change_password_handler(req, db)
    logging.debug(f"ChangePassword response: {resp}")
    return resp


if __name__ == "__main__":
    import uvicorn

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
