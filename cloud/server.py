#!/usr/bin/env python3
import os
import logging
import time
from contextlib import asynccontextmanager
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.exceptions import HTTPException as StarletteHTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
import uvicorn

import models
import handlers
from schemas import (
    SignupRequest,
    LoginRequest,
    ChallengeRequest,
    AuthenticateRequest,
    ChangeUsernameRequest,
    ChangePasswordRequest,
    UploadRequest,
    ListFilesRequest,
    DownloadFileRequest,
    DeleteFileRequest,
    GetOPKRequest,
    AddOPKsRequest,
    RemoveSharedFileRequest,
    ListSharedFilesRequest,
    ShareFileRequest,
    GetPreKeyBundleRequest,
    AddPreKeyBundleRequest,
    BackupTOFURequest,
    GetBackupTOFURequest,
    ListUsersRequest,
    ListSharedToRequest, 
    ListSharedFromRequest
)

# ─── Logging setup ──────────────────────────────────────────────────────────────
LOG_FILE = os.path.join(os.path.dirname(__file__), 'server_debug.log')
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s: %(message)s'
)
logger = logging.getLogger("fileshare")

def safe_request_log(req: Any) -> Dict[str, Any]:
    """
    Safely log request data by excluding sensitive fields.
    Returns a dict with only non-sensitive fields for logging.
    """
    if not req:
        return {}
        
    # Convert to dict if it's a Pydantic model
    data = req.model_dump() if hasattr(req, 'model_dump') else req
    
    # Fields that should never be logged
    sensitive_fields = {
        'password', 'salt', 'nonce', 'encrypted_privkey', 'encrypted_kek',
        'encrypted_file', 'encrypted_file_key', 'encrypted_data',
        'challenge', 'signature', 'pre_key', 'IK_pub', 'SPK_pub',
        'SPK_signature', 'EK_pub', 'backup_nonce', 'file_nonce',
        'dek_nonce', 'kek_nonce', 'privkey_nonce', 'encrypted_backup',
        'encrypted_dek', 'encrypted_privkey', 'encrypted_kek'
    }
    
    # Create safe copy without sensitive data
    safe_data = {}
    for key, value in data.items():
        if key not in sensitive_fields:
            safe_data[key] = value
        else:
            safe_data[key] = '[REDACTED]'
            
    return safe_data

def safe_log(level: int, msg: str):
    """Safely log a message at the specified level."""
    logger.log(level, msg)

# ─── Rate Limiting Setup ───────────────────────────────────────────────────────
class RateLimiter:
    def __init__(self):
        self.ip_attempts = defaultdict(list)  # IP -> list of timestamps
        self.user_attempts = defaultdict(list)  # username -> list of timestamps
        self.max_attempts = 5  # Maximum attempts per window
        self.window_seconds = 300  # 5 minute window
        self.backoff_base = 2  # Base for exponential backoff
        self.max_backoff = 3600  # Maximum backoff of 1 hour
        self.min_backoff = 30  # Minimum backoff of 30 seconds

        # File upload specific limits
        self.upload_attempts = defaultdict(list)  # username -> list of timestamps
        self.max_uploads = 10  # Maximum uploads per hour
        self.upload_window = 3600  # 1 hour window

    def _clean_old_attempts(self, attempts_list):
        now = time.time()
        return [ts for ts in attempts_list if now - ts < self.window_seconds]

    def _clean_old_uploads(self, uploads_list):
        now = time.time()
        return [ts for ts in uploads_list if now - ts < self.upload_window]

    def _get_backoff_seconds(self, attempt_count):
        backoff = min(self.backoff_base ** attempt_count, self.max_backoff)
        return max(backoff, self.min_backoff)

    def check_rate_limit(self, identifier: str, is_ip: bool = True):
        now = time.time()
        attempts_dict = self.ip_attempts if is_ip else self.user_attempts
        
        # Clean old attempts
        attempts_dict[identifier] = self._clean_old_attempts(attempts_dict[identifier])
        
        # Check if rate limit exceeded
        if len(attempts_dict[identifier]) >= self.max_attempts:
            backoff = self._get_backoff_seconds(len(attempts_dict[identifier]))
            raise HTTPException(
                status_code=429,
                detail=f"Too many attempts. Please try again in {backoff} seconds."
            )
        
        # Add new attempt
        attempts_dict[identifier].append(now)

    def check_upload_limit(self, username: str):
        now = time.time()
        # Clean old uploads
        self.upload_attempts[username] = self._clean_old_uploads(self.upload_attempts[username])
        
        # Check if upload limit exceeded
        if len(self.upload_attempts[username]) >= self.max_uploads:
            raise HTTPException(
                status_code=429,
                detail=f"Upload limit exceeded. Maximum {self.max_uploads} uploads per hour."
            )
        
        # Add new upload
        self.upload_attempts[username].append(now)

rate_limiter = RateLimiter()

async def rate_limit_ip(request: Request):
    client_ip = request.client.host
    rate_limiter.check_rate_limit(client_ip, is_ip=True)

async def rate_limit_user(request: Request):
    try:
        body = await request.json()
        username = body.get("username")
        if username:
            rate_limiter.check_rate_limit(username, is_ip=False)
    except:
        pass  # If we can't get the username, just continue

async def rate_limit_upload(request: Request):
    try:
        body = await request.json()
        username = body.get("username")
        if username:
            rate_limiter.check_upload_limit(username)
    except:
        pass  # If we can't get the username, just continue

# ─── Ensure database tables exist ────────────────────────────────────────────────
models.init_db()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Lifespan startup: opening DB connection")
    app.state.db = models.UserDB()
    try:
        yield
    finally:
        # Shutdown
        db = getattr(app.state, "db", None)
        if db:
            try:
                db.conn.close()
                logger.info("Lifespan shutdown: DB connection closed")
            except Exception:
                logger.exception("Error closing DB connection")

# ─── FastAPI app with lifespan ─────────────────────────────────────────────────
app = FastAPI(
    title="FileShare API",
    lifespan=lifespan
)

# ─── Security headers ───────────────────────────────────────────────────────────
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    
    # HSTS - Prevent protocol downgrade attacks and cookie hijacking
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    
    # X-Frame-Options - Prevent clickjacking
    response.headers["X-Frame-Options"] = "DENY"
    
    # X-Content-Type-Options - Prevent MIME-sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    
    # Content-Security-Policy - Prevent XSS and other injection attacks
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self'; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "base-uri 'self'; "
        "object-src 'none'"
    )
    
    # X-XSS-Protection - Additional XSS protection for older browsers
    response.headers["X-XSS-Protection"] = "1; mode=block"
    
    # Referrer-Policy - Control referrer information
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    # Permissions-Policy - Control browser features
    response.headers["Permissions-Policy"] = (
        "accelerometer=(), "
        "camera=(), "
        "geolocation=(), "
        "gyroscope=(), "
        "magnetometer=(), "
        "microphone=(), "
        "payment=(), "
        "usb=()"
    )
    
    return response

# ─── CORS ───────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Dependency to get DB ───────────────────────────────────────────────────────
def get_db():
    return app.state.db

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    # Let FastAPI render the JSON with the proper status code & detail
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Everything else is a 500
    logger.error("Unhandled exception during request", exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )

# ─── Health check ──────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok"}

# ─── Async endpoints ───────────────────────────────────────────────────────────
@app.post("/signup")
async def signup(
    req: SignupRequest,
    db: models.UserDB = Depends(get_db),
    _: None = Depends(rate_limit_ip),
    __: None = Depends(rate_limit_user)
):
    safe_log(logging.DEBUG, f"Signup request: {safe_request_log(req)}")
    resp = await run_in_threadpool(handlers.signup_handler, req, db)
    safe_log(logging.DEBUG, f"Signup response: {safe_request_log(resp)}")
    return resp

@app.post("/challenge")
async def challenge(
    req: ChallengeRequest,
    db: models.UserDB = Depends(get_db),
    _: None = Depends(rate_limit_ip),
    __: None = Depends(rate_limit_user)
):
    safe_log(logging.DEBUG, f"Challenge request: {safe_request_log(req)}")
    resp = await run_in_threadpool(handlers.challenge_handler, req, db)
    safe_log(logging.DEBUG, f"Challenge response: {safe_request_log(resp)}")
    return resp

@app.post("/login")
async def login(
    req: LoginRequest,
    db: models.UserDB = Depends(get_db),
    _: None = Depends(rate_limit_ip),
    __: None = Depends(rate_limit_user)
):
    safe_log(logging.DEBUG, f"Login request: {safe_request_log(req)}")
    # Step 1: generate challenge
    challenge_req = ChallengeRequest(username=req.username, operation="login")
    chal = await run_in_threadpool(handlers.challenge_handler, challenge_req, db)
    # Step 2: continue login
    full = await run_in_threadpool(handlers.login_handler_continue, req, db, chal["nonce"])
    safe_log(logging.DEBUG, f"Login response: {safe_request_log(full)}")
    return full

@app.post("/authenticate")
async def authenticate(
    req: AuthenticateRequest,
    db: models.UserDB = Depends(get_db),
    _: None = Depends(rate_limit_ip),
    __: None = Depends(rate_limit_user)
):
    safe_log(logging.DEBUG, f"Authenticate request: {safe_request_log(req)}")
    resp = await run_in_threadpool(handlers.authenticate_handler, req, db)
    safe_log(logging.DEBUG, f"Authenticate response: {safe_request_log(resp)}")
    return resp

@app.post("/change_username")
async def change_username(
    req: ChangeUsernameRequest,
    db: models.UserDB = Depends(get_db),
    _: None = Depends(rate_limit_ip),
    __: None = Depends(rate_limit_user)
):
    safe_log(logging.DEBUG, f"ChangeUsername request: {safe_request_log(req)}")
    resp = await run_in_threadpool(handlers.change_username_handler, req, db)
    safe_log(logging.DEBUG, f"ChangeUsername response: {safe_request_log(resp)}")
    return resp

@app.post("/change_password")
async def change_password(
    req: ChangePasswordRequest,
    db: models.UserDB = Depends(get_db),
    _: None = Depends(rate_limit_ip),
    __: None = Depends(rate_limit_user)
):
    safe_log(logging.DEBUG, f"ChangePassword request: {safe_request_log(req)}")
    resp = await run_in_threadpool(handlers.change_password_handler, req, db)
    safe_log(logging.DEBUG, f"ChangePassword response: {safe_request_log(resp)}")
    return resp

@app.post("/upload_file")
async def upload_file(
    req: UploadRequest, 
    db: models.UserDB = Depends(get_db),
    _: None = Depends(rate_limit_ip),
    __: None = Depends(rate_limit_user),
    ___: None = Depends(rate_limit_upload)
):
    safe_log(logging.DEBUG, f"Upload request: {safe_request_log(req)}")
    resp = await run_in_threadpool(handlers.upload_file_handler, req, db)
    safe_log(logging.DEBUG, f"Upload response: {safe_request_log(resp)}")
    return resp

@app.post("/list_files")
async def list_files(req: ListFilesRequest, db: models.UserDB = Depends(get_db)):
    safe_log(logging.DEBUG, f"ListFiles request: {safe_request_log(req)}")
    resp = await run_in_threadpool(handlers.list_files_handler, req, db)
    safe_log(logging.DEBUG, f"ListFiles response: {safe_request_log(resp)}")
    return resp

@app.post("/download_file")
async def download_file(req: DownloadFileRequest, db: models.UserDB = Depends(get_db)):
    safe_log(logging.DEBUG, f"Download request: {safe_request_log(req)}")
    resp = await run_in_threadpool(handlers.download_file_handler, req, db)
    safe_resp = safe_request_log(resp)
    safe_log(logging.DEBUG, f"Download response: {safe_resp}")
    return resp

@app.post("/delete_file")
async def delete_file(req: DeleteFileRequest, db: models.UserDB = Depends(get_db)):
    safe_log(logging.DEBUG, f"Delete request: {safe_request_log(req)}")
    resp = await run_in_threadpool(handlers.delete_file_handler, req, db)
    safe_log(logging.DEBUG, f"Delete response: {safe_request_log(resp)}")
    return resp

@app.post("/get_pre_key_bundle")
async def get_prekey_bundle(req: GetPreKeyBundleRequest, db: models.UserDB = Depends(get_db)):
    safe_log(logging.DEBUG, f"GetPreKeyBundle request: {safe_request_log(req)}")
    resp = await run_in_threadpool(handlers.get_prekey_bundle_handler, req, db)
    safe_log(logging.DEBUG, f"PreKeyBundle response: {safe_request_log(resp)}")
    return resp

@app.post("/add_pre_key_bundle")
async def add_prekey_bundle(req: AddPreKeyBundleRequest, db: models.UserDB = Depends(get_db)):
    safe_log(logging.DEBUG, f"AddPreKeyBundle request: {safe_request_log(req)}")
    resp = await run_in_threadpool(handlers.add_prekey_bundle_handler, req, db)
    safe_log(logging.DEBUG, f"AddPreKeyBundle response: {safe_request_log(resp)}")
    return resp

@app.post("/opk")
async def opk(req: GetOPKRequest, db: models.UserDB = Depends(get_db)):
    safe_log(logging.DEBUG, f"GetOPK request: {safe_request_log(req)}")
    resp = await run_in_threadpool(handlers.opk_handler, req, db)
    safe_log(logging.DEBUG, f"OPK response: {safe_request_log(resp)}")
    return resp

@app.post("/add_opks")
async def add_opks(req: AddOPKsRequest, db: models.UserDB = Depends(get_db)):
    safe_log(logging.DEBUG, f"AddOPKs request: {safe_request_log(req)}")
    resp = await run_in_threadpool(handlers.add_opks_handler, req, db)
    safe_log(logging.DEBUG, f"AddOPKs response: {safe_request_log(resp)}")
    return resp

@app.post("/share_file")
async def share_file(req: ShareFileRequest, db: models.UserDB = Depends(get_db)):
    safe_log(logging.DEBUG, f"ShareFile request: {safe_request_log(req)}")
    resp = await run_in_threadpool(handlers.share_file_handler, req, db)
    safe_log(logging.DEBUG, f"ShareFile response: {safe_request_log(resp)}")
    return resp

@app.post("/remove_shared_file")
async def remove_shared_file(req: RemoveSharedFileRequest, db: models.UserDB = Depends(get_db)):
    safe_log(logging.DEBUG, f"RemoveSharedFile request: {safe_request_log(req)}")
    resp = await run_in_threadpool(handlers.remove_shared_file_handler, req, db)
    safe_log(logging.DEBUG, f"RemoveSharedFile response: {safe_request_log(resp)}")
    return resp

@app.post("/list_shared_files")
async def list_shared_files(req: ListSharedFilesRequest, db: models.UserDB = Depends(get_db)):
    safe_log(logging.DEBUG, f"ListSharedFiles request: {safe_request_log(req)}")
    resp = await run_in_threadpool(handlers.list_shared_files_handler, req, db)
    safe_log(logging.DEBUG, f"ListSharedFiles response: {safe_request_log(resp)}")
    return resp

@app.post("/backup_tofu")
async def backup_tofu(req: BackupTOFURequest, db: models.UserDB = Depends(get_db)):
    safe_log(logging.DEBUG, f"BackupTOFU request: {safe_request_log(req)}")
    resp = await run_in_threadpool(handlers.backup_tofu_keys_handler, req, db)
    safe_log(logging.DEBUG, f"BackupTOFU response: {safe_request_log(resp)}")
    return resp

@app.post("/get_backup_tofu")
async def get_backup_tofu(req: GetBackupTOFURequest, db: models.UserDB = Depends(get_db)):
    safe_log(logging.DEBUG, f"GetBackupTOFU request: {safe_request_log(req)}")
    resp = await run_in_threadpool(handlers.get_backup_tofu_keys_handler, req, db)
    safe_log(logging.DEBUG, f"GetBackupTOFU response: {safe_request_log(resp)}")
    return resp

@app.post("/list_users")
async def list_users(req: ListUsersRequest, db: models.UserDB = Depends(get_db)):
    safe_log(logging.DEBUG, f"ListUsers request: {safe_request_log(req)}")
    resp = await run_in_threadpool(handlers.list_users_handler, req, db)
    safe_log(logging.DEBUG, f"ListUsers response: {safe_request_log(resp)}")
    return resp

@app.post("/list_shared_to")
async def list_shared_to(req: ListSharedToRequest, db: models.UserDB = Depends(get_db)):
    safe_log(logging.DEBUG, f"ListSharedTo request: {safe_request_log(req)}")
    resp = await run_in_threadpool(handlers.list_shared_to_handler, req, db)
    safe_log(logging.DEBUG, f"ListSharedTo response: {safe_request_log(resp)}")
    return resp

@app.post("/list_shared_from")
async def list_shared_from(req: ListSharedFromRequest, db: models.UserDB = Depends(get_db)):
    safe_log(logging.DEBUG, f"ListSharedFrom request: {safe_request_log(req)}")
    resp = await run_in_threadpool(handlers.list_shared_from_handler, req, db)
    safe_log(logging.DEBUG, f"ListSharedFrom response: {safe_request_log(resp)}")
    return resp

# ─── Run with TLS ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    host     = os.environ.get('FS_HOST', '0.0.0.0')
    port     = int(os.environ.get('FS_HTTPS_PORT', '3210'))
    certfile = os.environ.get('SSL_CERTFILE', 'cert.pem')
    keyfile  = os.environ.get('SSL_KEYFILE', 'key.pem')

    if not (os.path.exists(certfile) and os.path.exists(keyfile)):
        logger.error(f"Missing cert or key: '{certfile}' / '{keyfile}'")
        raise SystemExit("TLS cert/key not found; please generate them via OpenSSL")

    logger.info(f"Starting HTTPS server on {host}:{port}")
    uvicorn.run(
        app,
        host=host,
        port=port,
        ssl_certfile=certfile,
        ssl_keyfile=keyfile,
        log_config=None,
    )

