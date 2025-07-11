#!/usr/bin/env python3
import os
import logging
from contextlib import asynccontextmanager

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
    ListSharedFromRequest,
    ListSharersRequest,
    RetrieveFileDEKRequest,
    DownloadSharedFileRequest,
    ListMatchingUsersRequest,
    PreviewSharedFileRequest,
    ClearUserOPKsRequest,
    GetOPKCountRequest
)

# ─── Logging setup ──────────────────────────────────────────────────────────────
LOG_FILE = os.path.join(os.path.dirname(__file__), 'server_debug.log')
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s: %(message)s'
)
logger = logging.getLogger("fileshare")

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
        if db and hasattr(db, 'pool'):
            try:
                db.pool.close()
                logger.info("Lifespan shutdown: DB connection pool closed")
            except Exception as e:
                logger.error(f"Error closing DB connection pool: {str(e)}")

# ─── FastAPI app with lifespan ─────────────────────────────────────────────────
app = FastAPI(
    title="FileShare API",
    lifespan=lifespan
)

# ─── Security headers (HSTS) ───────────────────────────────────────────────────
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    try:
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response
    except Exception as e:
        logger.error("Error in security headers middleware", exc_info=e)
        raise

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
async def signup(req: SignupRequest, db: models.UserDB = Depends(get_db)):
    logger.debug(f"SignupRequest body: {req.model_dump_json()}")
    resp = await run_in_threadpool(handlers.signup_handler, req, db)
    logger.debug(f"Signup response: {resp}")
    return resp

@app.post("/challenge")
async def challenge(req: ChallengeRequest, db: models.UserDB = Depends(get_db)):
    logger.debug(f"ChallengeRequest body: {req.model_dump_json()}")
    resp = await run_in_threadpool(handlers.challenge_handler, req, db)
    logger.debug(f"Challenge response: {resp}")
    return resp

@app.post("/login")
async def login(req: LoginRequest, db: models.UserDB = Depends(get_db)):
    logger.debug(f"LoginRequest body: {req.model_dump_json()}")
    # Step 1: generate challenge
    challenge_req = ChallengeRequest(username=req.username, operation="login")
    chal = await run_in_threadpool(handlers.challenge_handler, challenge_req, db)
    # Step 2: continue login
    full = await run_in_threadpool(handlers.login_handler_continue, req, db, chal["nonce"])
    logger.debug(f"Login response: {full}")
    return full

@app.post("/authenticate")
async def authenticate(req: AuthenticateRequest, db: models.UserDB = Depends(get_db)):
    logger.debug(f"AuthenticateRequest body: {req.model_dump_json()}")
    resp = await run_in_threadpool(handlers.authenticate_handler, req, db)
    logger.debug(f"Authenticate response: {resp}")
    return resp

@app.post("/change_username")
async def change_username(req: ChangeUsernameRequest, db: models.UserDB = Depends(get_db)):
    logger.debug(f"ChangeUsernameRequest body: {req.model_dump_json()}")
    resp = await run_in_threadpool(handlers.change_username_handler, req, db)
    logger.debug(f"ChangeUsername response: {resp}")
    return resp

@app.post("/change_password")
async def change_password(req: ChangePasswordRequest, db: models.UserDB = Depends(get_db)):
    logger.debug(f"ChangePasswordRequest body: {req.model_dump_json()}")
    resp = await run_in_threadpool(handlers.change_password_handler, req, db)
    logger.debug(f"ChangePassword response: {resp}")
    return resp

@app.post("/upload_file")
async def upload_file(req: UploadRequest, db: models.UserDB = Depends(get_db)):
    logger.debug(f"UploadRequest body: {req.model_dump_json(exclude={'encrypted_file'})}")
    resp = await run_in_threadpool(handlers.upload_file_handler, req, db)
    logger.debug(f"UploadFile response: {resp}")
    return resp

@app.post("/retrieve_file_dek")
async def retrieve_file_dek(req: RetrieveFileDEKRequest, db: models.UserDB = Depends(get_db)):
    logger.debug(f"RetrieveFileDEKRequest body: {req.model_dump_json()}")
    resp = await run_in_threadpool(handlers.retrieve_file_dek_handler, req, db)
    logger.debug(f"RetrieveFileDEK response: {resp}")
    return resp

@app.post("/list_files")
async def list_files(req: ListFilesRequest, db: models.UserDB = Depends(get_db)):
    logger.debug(f"ListFilesRequest body: {req.model_dump_json()}")
    resp = await run_in_threadpool(handlers.list_files_handler, req, db)
    logger.debug(f"ListFiles response: {resp}")
    return resp

@app.post("/download_file")
async def download_file(req: DownloadFileRequest, db: models.UserDB = Depends(get_db)):
    logger.debug(f"DownloadFileRequest body: {req.model_dump_json()}")
    resp = await run_in_threadpool(handlers.download_file_handler, req, db)
    safe_resp = resp.copy()
    safe_resp.pop("encrypted_file", None)
    logger.debug(f"DownloadFile response: {safe_resp}")
    return resp

@app.post("/delete_file")
async def delete_file(req: DeleteFileRequest, db: models.UserDB = Depends(get_db)):
    logger.debug(f"DeleteFileRequest body: {req.model_dump_json()}")
    resp = await run_in_threadpool(handlers.delete_file_handler, req, db)
    logger.debug(f"DeleteFile response: {resp}")
    return resp

@app.post("/get_pre_key_bundle")
async def get_prekey_bundle(req: GetPreKeyBundleRequest, db: models.UserDB = Depends(get_db)):
    logger.debug(f"GetPreKeyBundleRequest body: {req.model_dump_json()}")
    resp = await run_in_threadpool(handlers.get_prekey_bundle_handler, req, db)
    logger.debug(f"PreKeyBundle response: {resp}")
    return resp

@app.post("/add_pre_key_bundle")
async def add_prekey_bundle(req: AddPreKeyBundleRequest, db: models.UserDB = Depends(get_db)):
    logger.debug(f"AddPreKeyBundleRequest body: {req.model_dump_json()}")
    resp = await run_in_threadpool(handlers.add_prekey_bundle_handler, req, db)
    logger.debug(f"AddPreKeyBundle response: {resp}")
    return resp


@app.post("/opk")
async def opk(req: GetOPKRequest, db: models.UserDB = Depends(get_db)):
    logger.debug(f"GetOPKRequest body: {req.model_dump_json()}")
    resp = await run_in_threadpool(handlers.get_opk_handler, req, db)
    logger.debug(f"OPK response: {resp}")
    return resp

@app.post("/add_opks")
async def add_opks(req: AddOPKsRequest, db: models.UserDB = Depends(get_db)):
    logger.debug(f"AddOPKsRequest body: {req.model_dump_json()}")
    resp = await run_in_threadpool(handlers.add_opks_handler, req, db)
    logger.debug(f"AddOPKs response: {resp}")
    return resp

@app.post("/share_file")
async def share_file(req: ShareFileRequest, db: models.UserDB = Depends(get_db)):
    logger.debug(f"ShareFileRequest body: {req.model_dump_json()}")
    resp = await run_in_threadpool(handlers.share_file_handler, req, db)
    logger.debug(f"ShareFile response: {resp}")
    return resp

@app.post("/remove_shared_file")
async def remove_shared_file(req: RemoveSharedFileRequest, db: models.UserDB = Depends(get_db)):
    logger.debug(f"RemoveSharedFileRequest body: {req.model_dump_json()}")
    resp = await run_in_threadpool(handlers.remove_shared_file_handler, req, db)
    logger.debug(f"RemoveSharedFile response: {resp}")
    return resp

@app.post("/list_shared_files")
async def list_shared_files(req: ListSharedFilesRequest, db: models.UserDB = Depends(get_db)):
    logger.debug(f"ListSharedFilesRequest body: {req.model_dump_json()}")
    resp = await run_in_threadpool(handlers.list_shared_files_handler, req, db)
    logger.debug(f"ListSharedFiles response: {resp}")
    return resp

@app.post("/download_shared_file")
async def download_shared_file(req: DownloadSharedFileRequest, db: models.UserDB = Depends(get_db)):
    logger.debug(f"DownloadSharedFileRequest body: {req.model_dump_json()}")
    resp = await run_in_threadpool(handlers.download_shared_file_handler, req, db)
    logger.debug(f"DownloadSharedFile response: {resp}")
    return resp

@app.post("/preview_shared_file")
async def preview_shared_file(req: PreviewSharedFileRequest, db: models.UserDB = Depends(get_db)):
    logger.debug(f"PreviewSharedFileRequest body: {req.model_dump_json()}")
    resp = await run_in_threadpool(handlers.preview_shared_file_handler, req, db)
    logger.debug(f"PreviewSharedFile response: {resp}")
    return resp

@app.post("/backup_tofu")
async def backup_tofu(req: BackupTOFURequest, db: models.UserDB = Depends(get_db)):
    logger.debug(f"BackupTOFURequest body: {req.model_dump_json()}")
    resp = await run_in_threadpool(handlers.backup_tofu_keys_handler, req, db)
    logger.debug(f"BackupTOFU response: {resp}")
    return resp

@app.post("/get_backup_tofu")
async def get_backup_tofu(req: GetBackupTOFURequest, db: models.UserDB = Depends(get_db)):
    logger.debug(f"GetBackupTOFURequest body: {req.model_dump_json()}")
    resp = await run_in_threadpool(handlers.get_backup_tofu_keys_handler, req, db)
    logger.debug(f"GetBackupTOFU response: {resp}")
    return resp

@app.post("/list_users")
async def list_users(req: ListUsersRequest, db: models.UserDB = Depends(get_db)):
    logger.debug(f"ListUsersRequest body: {req.model_dump_json()}")
    resp = await run_in_threadpool(handlers.list_users_handler, req, db)
    logger.debug(f"ListUsers response: {resp}")
    return resp

# New: list the files I have shared *to* a given user
@app.post("/list_shared_to")
async def list_shared_to(req: ListSharedToRequest,  db: models.UserDB = Depends(get_db)):
    logger.debug(f"ListSharedToRequest body: {req.model_dump_json()}")
    resp = await run_in_threadpool(handlers.list_shared_to_handler, req, db)
    logger.debug(f"ListSharedTo response: {resp}")
    return resp

# New: list the files shared *to me* *from* a given user
@app.post("/list_shared_from")
async def list_shared_from(req: ListSharedFromRequest, db: models.UserDB = Depends(get_db)):
    logger.debug(f"ListSharedFromRequest body: {req.model_dump_json()}")
    resp = await run_in_threadpool(handlers.list_shared_from_handler, req, db)
    logger.debug(f"ListSharedFrom response: {resp}")
    return resp


@app.post("/list_matching_users")
async def list_matching_users(req: ListMatchingUsersRequest, db: models.UserDB = Depends(get_db)):
    logger.debug(f"ListMatchingUsersRequest body: {req.model_dump_json()}")
    resp = await run_in_threadpool(handlers.list_matching_users_handler, req, db)
    logger.debug(f"ListMatchingUsers response: {resp}")
    return resp

@app.post("/clear_user_opks")
async def clear_user_opks(req: ClearUserOPKsRequest, db: models.UserDB = Depends(get_db)):
    """
    Test endpoint to clear all OPKs for a user.
    This is for testing X3DH without OPKs.
    """
    return handlers.clear_user_opks_handler(req, db)

@app.post("/get_opk_count")
async def get_opk_count(req: GetOPKCountRequest, db: models.UserDB = Depends(get_db)):
    logger.debug(f"GetOPKCountRequest body: {req.model_dump_json()}")
    resp = await run_in_threadpool(handlers.get_opk_count_handler, req, db)
    logger.debug(f"GetOPKCount response: {resp}")
    return resp

@app.post("/list_sharers")
async def list_sharers(req: ListSharersRequest, db: models.UserDB = Depends(get_db)):
    logger.debug(f"ListSharersRequest body: {req.model_dump_json()}")
    resp = await run_in_threadpool(handlers.list_sharers_handler, req, db)
    logger.debug(f"ListSharers response: {resp}")
    return resp

if __name__ == "__main__":
    # When behind Apache, we only serve HTTP on 127.0.0.1:3210.
    # Apache will handle SSL on port 443 and reverse‐proxy into us.
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=3210,
        log_config=None,
    )
