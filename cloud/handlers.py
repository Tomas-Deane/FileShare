# cloud/handlers.py
#!/usr/bin/env python3
import base64
import secrets
import logging
from fastapi import HTTPException
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
    BackupTOFURequest,
    GetBackupTOFURequest,
    GetPreKeyBundleRequest,
    AddPreKeyBundleRequest,
    ListUsersRequest,
    ListUsersResponse,
    UserData,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

import models

def verify_signature(username: str, nonce: str, signature: str) -> bool:
    """Verify a signature for a given username and nonce."""
    user = models.UserDB().get_user(username)
    if not user:
        return False
    
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(base64.b64decode(signature), base64.b64decode(nonce))
        return True
    except InvalidSignature:
        return False

# --- CHALLENGE HANDLER --------------------------------------------
def challenge_handler(req: ChallengeRequest, db: models.UserDB):
    logging.debug(f"Challenge: {req.model_dump_json()}")
    user = db.get_user(req.username)
    if not user:
        logging.warning(f"Unknown user '{req.username}' at challenge")
        raise HTTPException(status_code=404, detail="Unknown user")

    user_id = user["user_id"]
    challenge = secrets.token_bytes(32)
    db.add_challenge(user_id, req.operation, challenge)
    logging.debug(f"Stored challenge for user_id={user_id} op={req.operation}: {challenge.hex()}")

    return {
        "status": "challenge",
        "nonce": base64.b64encode(challenge).decode()
    }

# --- LOGIN CONTINUATION ------------------------------------------------
def login_handler_continue(req: LoginRequest, db: models.UserDB, b64_nonce: str):
    logging.debug(f"Login continuation: {req.model_dump_json()}")
    user = db.get_user(req.username)
    if not user:
        logging.warning(f"Unknown user '{req.username}' in login continuation")
        raise HTTPException(status_code=404, detail="Unknown user")

    return {
        "status": "challenge",
        "nonce": b64_nonce,
        "salt": base64.b64encode(user["salt"]).decode(),
        "argon2_opslimit": user["argon2_opslimit"],
        "argon2_memlimit": user["argon2_memlimit"],
        "encrypted_privkey": base64.b64encode(user["encrypted_privkey"]).decode(),
        "privkey_nonce": base64.b64encode(user["privkey_nonce"]).decode(),
        "encrypted_kek": base64.b64encode(user["encrypted_kek"]).decode(),
        "kek_nonce": base64.b64encode(user["kek_nonce"]).decode()
    }

# --- SIGNUP ------------------------------------------------------------
def signup_handler(req: SignupRequest, db: models.UserDB):
    logging.debug(f"Signup: {req.model_dump_json()}")
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
        base64.b64decode(req.privkey_nonce),
        base64.b64decode(req.encrypted_kek),
        base64.b64decode(req.kek_nonce)
    )

    logging.info(f"Signup successful for '{req.username}'")
    return {"status": "ok"}

# --- AUTHENTICATE (LOGIN COMPLETE) --------------------------------------
def authenticate_handler(req: AuthenticateRequest, db: models.UserDB):
    logging.debug(f"Authenticate: {req.model_dump_json()}")
    user = db.get_user(req.username)
    if not user:
        logging.warning(f"Unknown user '{req.username}' at authenticate")
        raise HTTPException(status_code=404, detail="Unknown user")

    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(user_id, "login")
    if stored is None or provided != stored:
        logging.warning(f"No valid pending challenge for user_id={user_id} (login)")
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, provided)
        logging.info(f"Signature valid for user_id={user_id} (login)")
        db.delete_challenge(user_id)
        return {"status": "ok", "message": "login successful"}
    except InvalidSignature:
        logging.warning(f"Bad signature for user_id={user_id} (login)")
        db.delete_challenge(user_id)
        raise HTTPException(status_code=401, detail="Bad signature")

# --- CHANGE USERNAME ------------------------------------------------------
def change_username_handler(req: ChangeUsernameRequest, db: models.UserDB):
    logging.debug(f"ChangeUsername: {req.model_dump_json()}")
    user = db.get_user(req.username)
    if not user:
        logging.warning(f"Unknown user '{req.username}' at change_username")
        raise HTTPException(status_code=404, detail="Unknown user")

    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(user_id, "change_username")
    if stored is None or provided != stored:
        logging.warning(f"No valid pending challenge for user_id={user_id} (change_username)")
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, req.new_username.encode())
        db.update_username(req.username, req.new_username)
        logging.info(f"Username changed from '{req.username}' to '{req.new_username}'")
        db.delete_challenge(user_id)
        return {"status": "ok", "message": "username changed"}
    except InvalidSignature:
        logging.warning(f"Bad signature for change_username of user_id={user_id}")
        db.delete_challenge(user_id)
        raise HTTPException(status_code=401, detail="Bad signature")

# --- CHANGE PASSWORD ------------------------------------------------------
def change_password_handler(req: ChangePasswordRequest, db: models.UserDB):
    logging.debug(f"ChangePassword: {req.model_dump_json()}")
    user = db.get_user(req.username)
    if not user:
        logging.warning(f"Unknown user '{req.username}' at change_password")
        raise HTTPException(status_code=404, detail="Unknown user")

    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(user_id, "change_password")
    if stored is None or provided != stored:
        logging.warning(f"No valid pending challenge for user_id={user_id} (change_password)")
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    encrypted_privkey = base64.b64decode(req.encrypted_privkey)
    encrypted_kek     = base64.b64decode(req.encrypted_kek)
    signature         = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, encrypted_privkey)
        db.update_password(
            req.username,
            base64.b64decode(req.salt),
            req.argon2_opslimit,
            req.argon2_memlimit,
            encrypted_privkey,
            base64.b64decode(req.privkey_nonce),
            encrypted_kek,
            base64.b64decode(req.kek_nonce)
        )
        logging.info(f"Password changed for user_id={user_id}")
        db.delete_challenge(user_id)
        return {"status": "ok", "message": "password changed"}
    except InvalidSignature:
        logging.warning(f"Bad signature for change_password of user_id={user_id}")
        db.delete_challenge(user_id)
        raise HTTPException(status_code=401, detail="Bad signature")

# --- FILE UPLOAD ------------------------------------------------------
def upload_file_handler(req: UploadRequest, db: models.UserDB):
    logging.debug(f"UploadFile: {req.model_dump_json(exclude={'encrypted_file'})}")
    user = db.get_user(req.username)
    if not user:
        logging.warning(f"Unknown user '{req.username}' at upload_file")
        raise HTTPException(status_code=404, detail="Unknown user")

    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored  = db.get_pending_challenge(user_id, "upload_file")
    if stored is None or provided != stored:
        logging.warning(f"No valid pending challenge for user_id={user_id} (upload_file)")
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    encrypted_dek = base64.b64decode(req.encrypted_dek)
    signature     = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, encrypted_dek)
        db.add_file(
            req.username,
            req.filename,
            base64.b64decode(req.encrypted_file),
            base64.b64decode(req.file_nonce),
            encrypted_dek,
            base64.b64decode(req.dek_nonce)
        )
        logging.info(f"File '{req.filename}' uploaded for user_id={user_id}")
        db.delete_challenge(user_id)
        return {"status": "ok", "message": "file uploaded"}
    except InvalidSignature:
        logging.warning(f"Bad signature for upload_file of user_id={user_id}")
        db.delete_challenge(user_id)
        raise HTTPException(status_code=401, detail="Bad signature")

# --- LIST FILES ------------------------------------------------------
def list_files_handler(req: ListFilesRequest, db: models.UserDB):
    logging.debug(f"ListFiles: {req.model_dump_json()}")
    user = db.get_user(req.username)
    if not user:
        logging.warning(f"Unknown user '{req.username}' at list_files")
        raise HTTPException(status_code=404, detail="Unknown user")

    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored  = db.get_pending_challenge(user_id, "list_files")
    if stored is None or provided != stored:
        logging.warning(f"No valid pending challenge for user_id={user_id} (list_files)")
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, provided)
        files = db.list_files(req.username)
        db.delete_challenge(user_id)
        return {"status": "ok", "files": files}
    except InvalidSignature:
        logging.warning(f"Bad signature for list_files of user_id={user_id}")
        db.delete_challenge(user_id)
        raise HTTPException(status_code=401, detail="Bad signature")

# --- DOWNLOAD FILE ------------------------------------------------------
def download_file_handler(req: DownloadFileRequest, db: models.UserDB):
    logging.debug(f"DownloadFile: {req.model_dump_json()}")
    user = db.get_user(req.username)
    if not user:
        logging.warning(f"Unknown user '{req.username}' at download_file")
        raise HTTPException(status_code=404, detail="Unknown user")

    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored  = db.get_pending_challenge(user_id, "download_file")
    if stored is None or provided != stored:
        logging.warning(f"No valid pending challenge for user_id={user_id} (download_file)")
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, req.filename.encode())
        record = db.get_file(req.username, req.filename)
        if not record:
            logging.warning(f"File '{req.filename}' not found for user_id={user_id}")
            raise HTTPException(status_code=404, detail="File not found")
        db.delete_challenge(user_id)
        return {
            "status": "ok",
            "encrypted_file": base64.b64encode(record["encrypted_file"]).decode(),
            "file_nonce":      base64.b64encode(record["file_nonce"]).decode(),
            "encrypted_dek":   base64.b64encode(record["encrypted_dek"]).decode(),
            "dek_nonce":       base64.b64encode(record["dek_nonce"]).decode()
        }
    except InvalidSignature:
        logging.warning(f"Bad signature for download_file of user_id={user_id}")
        db.delete_challenge(user_id)
        raise HTTPException(status_code=401, detail="Bad signature")

# --- DELETE FILE ------------------------------------------------------
def delete_file_handler(req: DeleteFileRequest, db: models.UserDB):
    logging.debug(f"DeleteFile: {req.model_dump_json()}")
    user = db.get_user(req.username)
    if not user:
        logging.warning(f"Unknown user '{req.username}' at delete_file")
        raise HTTPException(status_code=404, detail="Unknown user")

    user_id  = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored   = db.get_pending_challenge(user_id, "delete_file")
    if stored is None or provided != stored:
        logging.warning(f"No valid pending challenge for user_id={user_id} (delete_file)")
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, req.filename.encode())

        db.delete_file(req.username, req.filename)
        logging.info(f"File '{req.filename}' deleted for user_id={user_id}")
        db.delete_challenge(user_id)
        return {"status": "ok", "message": "file deleted"}
    except InvalidSignature:
        logging.warning(f"Bad signature for delete_file of user_id={user_id}")
        db.delete_challenge(user_id)
        raise HTTPException(status_code=401, detail="Bad signature")

# --- BACKUP TOFU KEYS ------------------------------------------------------
def backup_tofu_keys_handler(req: BackupTOFURequest, db: models.UserDB):
    logging.debug(f"BackupTOFU: {req.model_dump_json()}")
    user = db.get_user(req.username)
    if not user:
        raise HTTPException(status_code=404, detail="Unknown user")

    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(user_id, "backup_tofu")
    if stored is None or provided != stored:
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, provided)
        
        # Store the encrypted backup
        db.add_tofu_backup(
            user_id,
            base64.b64decode(req.encrypted_backup),
            base64.b64decode(req.backup_nonce)
        )
        
        db.delete_challenge(user_id)
        return {"status": "ok", "message": "TOFU backup stored"}
    except InvalidSignature:
        db.delete_challenge(user_id)
        raise HTTPException(status_code=401, detail="Bad signature")

# --- GET BACKUP TOFU KEYS ------------------------------------------------------
def get_backup_tofu_keys_handler(req: GetBackupTOFURequest, db: models.UserDB):
    logging.debug(f"GetBackupTOFU: {req.model_dump_json()}")
    user = db.get_user(req.username)
    if not user:
        raise HTTPException(status_code=404, detail="Unknown user")

    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(user_id, "get_backup_tofu")
    if stored is None or provided != stored:
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, provided)
        
        backup = db.get_tofu_backup(user_id)
        if not backup:
            raise HTTPException(status_code=404, detail="No TOFU backup found")
        
        logging.debug(f"Found backup: {backup is not None}")
        return {
            "status": "ok",
            "encrypted_backup": base64.b64encode(backup["encrypted_data"]).decode(),
            "backup_nonce": base64.b64encode(backup["backup_nonce"]).decode()
        }
    except InvalidSignature:
        db.delete_challenge(user_id)
        raise HTTPException(status_code=401, detail="Bad signature")

# --- PREKEY BUNDLE ------------------------------------------------------
#get prekey bundle
def get_prekey_bundle_handler(req: GetPreKeyBundleRequest, db: models.UserDB):
    logging.debug(f"GetPreKeyBundle: {req.model_dump_json()}")
    user = db.get_user(req.username)
    if not user:
        raise HTTPException(status_code=404, detail="Unknown user")
    
    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(user_id, "get_prekey_bundle")
    if stored is None or provided != stored:
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")
    
    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, provided)
        
        bundle = db.get_pre_key_bundle(user_id)
        if not bundle:
            raise HTTPException(status_code=404, detail="No prekey bundle found")
        
        return {
            "status": "ok",
            "prekey_bundle": bundle
        }
    except InvalidSignature:
        db.delete_challenge(user_id)
        raise HTTPException(status_code=401, detail="Bad signature")
    
#add prekey bundle
def add_prekey_bundle_handler(req: AddPreKeyBundleRequest, db: models.UserDB):
    logging.debug(f"AddPreKeyBundle: {req.model_dump_json()}")
    user = db.get_user(req.username)
    if not user:
        raise HTTPException(status_code=404, detail="Unknown user")
    
    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(user_id, "add_prekey_bundle")
    if stored is None or provided != stored:
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")
    
    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, provided)
        
        db.add_prekey_bundle(user_id, req.IK_pub, req.SPK_pub, req.SPK_signature)
        db.delete_challenge(user_id)
        return {"status": "ok", "message": "Prekey bundle added"}
    except InvalidSignature:
        db.delete_challenge(user_id)
        raise HTTPException(status_code=401, detail="Bad signature")

def list_users_handler(req: ListUsersRequest, db: models.UserDB) -> ListUsersResponse:
    """List all users in the system."""
    logging.debug(f"ListUsers: {req.model_dump_json()}")
    user = db.get_user(req.username)
    if not user:
        logging.warning(f"Unknown user '{req.username}' at list_users")
        raise HTTPException(status_code=404, detail="Unknown user")

    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(user_id, "list_users")
    if stored is None or provided != stored:
        logging.warning(f"No valid pending challenge for user_id={user_id} (list_users)")
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, provided)
        
        # Get all users
        users = db.get_all_users()
        
        # Delete the challenge after successful verification
        db.delete_challenge(user_id)
        
        # Return user list - handle both tuple and dict results
        return ListUsersResponse(
            status="ok",
            users=[
                UserData(
                    id=user[0] if isinstance(user, tuple) else user["id"],
                    username=user[1] if isinstance(user, tuple) else user["username"]
                )
                for user in users
            ]
        )
    except InvalidSignature:
        logging.warning(f"Bad signature for list_users of user_id={user_id}")
        db.delete_challenge(user_id)
        raise HTTPException(status_code=401, detail="Bad signature")

