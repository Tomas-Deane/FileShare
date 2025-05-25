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
    encrypted_kek: str
    kek_nonce: str


class LoginRequest(BaseModel):
    username: str


class ChallengeRequest(BaseModel):
    username: str
    operation: str  # e.g. "login", "change_username", ...


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
    encrypted_kek: str
    kek_nonce: str
    nonce: str
    signature: str


class UploadRequest(BaseModel):
    username: str
    filename: str
    encrypted_file: str
    file_nonce: str
    encrypted_dek: str
    dek_nonce: str
    nonce: str
    signature: str


class ListFilesRequest(BaseModel):
    username: str
    nonce: str
    signature: str


class DownloadFileRequest(BaseModel):
    username: str
    filename: str
    nonce: str
    signature: str


class DeleteFileRequest(BaseModel):
    username: str
    filename: str
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
    challenge_req = ChallengeRequest(username=req.username, operation="login")
    chal = handlers.challenge_handler(challenge_req, db)
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


@app.post("/upload_file")
def upload_file(req: UploadRequest):
    # don't log the full encrypted payload
    logging.debug(
        "UploadRequest body: %s",
        req.json(exclude={"encrypted_file"})
    )
    resp = handlers.upload_file_handler(req, db)
    logging.debug(f"UploadFile response: {resp}")
    return resp


@app.post("/list_files")
def list_files(req: ListFilesRequest):
    logging.debug(f"ListFilesRequest body: {req.json()}")
    resp = handlers.list_files_handler(req, db)
    logging.debug(f"ListFiles response: {resp}")
    return resp


@app.post("/download_file")
def download_file(req: DownloadFileRequest):
    logging.debug(f"DownloadFileRequest body: {req.json()}")
    resp = handlers.download_file_handler(req, db)
    # strip out bulky encrypted_file before logging
    safe_resp = resp.copy()
    safe_resp.pop("encrypted_file", None)
    logging.debug(f"DownloadFile response: {safe_resp}")
    return resp


@app.post("/delete_file")
def delete_file(req: DeleteFileRequest):
    logging.debug(f"DeleteFileRequest body: {req.json()}")
    resp = handlers.delete_file_handler(req, db)
    logging.debug(f"DeleteFile response: {resp}")
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