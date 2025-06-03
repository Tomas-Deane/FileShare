#!/usr/bin/env python3
import base64
import secrets
import logging
import re
from fastapi import HTTPException
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
import datetime

import models
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
    AddOPKsRequest,
    ShareFileRequest,
    RemoveSharedFileRequest,
    ListSharedFilesRequest,
    ListSharedToRequest,
    ListSharedFromRequest,
    SharedFileResponse,
    OPKResponse, 
    GetOPKRequest,
    RetrieveFileDEKRequest,
    DownloadSharedFileRequest,
    ListMatchingUsersRequest,
    ListSharersRequest,
    ClearUserOPKsRequest,
)

# ─── Allowed operations for challenge requests ────────────────────────────────
ALLOWED_OPERATIONS = {
    "login",
    "change_username",
    "change_password",
    "upload_file",
    "list_files",
    "download_file",
    "retrieve_file_dek",
    "delete_file",
    "get_pre_key_bundle",
    "add_pre_key_bundle",
    "list_users",
    "add_opks",
    "get_opk",
    "share_file",
    "list_shared_files",
    "list_shared_to",
    "list_shared_from",
    "remove_shared_file",
    "download_shared_file",
    "backup_tofu",
    "get_backup_tofu",
    "list_matching_users",
    "list_sharers"
    "clear_user_opks"
}

def validate_filename(filename: str) -> bool:
    """
    Validate a filename to prevent directory traversal and ensure it only contains safe characters.

    Rules:
    1. No directory traversal sequences 
    2. No null bytes
    3. Only alphanumeric characters, dots, hyphens, and underscores
    4. Maximum length of 255 characters
    5. No leading or trailing dots
    """
    if not filename or len(filename) > 255:
        return False

    # Check for directory traversal or path separators
    if '..' in filename or '/' in filename or '\\' in filename:
        return False

    # Check for null bytes
    if '\0' in filename:
        return False

    # Check leading/trailing dots
    if filename.startswith('.') or filename.endswith('.'):
        return False

    # Only allow alphanumeric, dots, hyphens, and underscores
    if not re.match(r'^[a-zA-Z0-9._-]+$', filename):
        return False

    return True

def validate_base64(b64_string: str, field_name: str) -> bytes:
    """
    Validate a Base64 string and return its decoded bytes.
    Raises HTTPException if invalid.
    """
    if not b64_string:
        raise HTTPException(status_code=400, detail=f"Empty {field_name}")

    # Only valid Base64 characters plus padding
    if not re.match(r'^[A-Za-z0-9+/]*={0,2}$', b64_string):
        raise HTTPException(status_code=400, detail=f"Invalid Base64 characters in {field_name}")

    try:
        return base64.b64decode(b64_string)
    except Exception as e:
        logging.warning(f"Invalid Base64 in {field_name}: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Invalid Base64 for {field_name}")

def verify_signature(username: str, nonce: str, signature: str) -> bool:
    """
    Verify a signature for a given username and nonce.
    Returns True if valid, False otherwise.
    """
    user = models.UserDB().get_user(username)
    if not user:
        return False

    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(base64.b64decode(signature), base64.b64decode(nonce))
        return True
    except (InvalidSignature, Exception):
        return False

# --- CHALLENGE HANDLER --------------------------------------------
def challenge_handler(req: ChallengeRequest, db: models.UserDB):
    logging.debug(f"Challenge: {req.model_dump_json()}")

    # Validate operation
    if req.operation not in ALLOWED_OPERATIONS:
        logging.warning(f"Invalid operation '{req.operation}' requested")
        raise HTTPException(status_code=400, detail="Invalid operation")

    # Generate a random 32-byte nonce
    challenge = secrets.token_bytes(32)

    # Only store challenge if the user actually exists
    user = db.get_user(req.username)
    if user:
        user_id = user["user_id"]
        db.add_challenge(user_id, req.operation, challenge)
        logging.debug(f"Stored challenge for user_id={user_id} op={req.operation}: {base64.b64encode(challenge).decode()}")
    else:
        logging.debug(f"Generated challenge for non-existent user '{req.username}' (not stored)")

    logging.debug(f"Challenge timestamp: {datetime.datetime.utcnow()}")
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
        raise HTTPException(status_code=400, detail="Invalid credentials")

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
    # 1) check if user already exists
    if db.get_user(req.username):
        logging.warning(f"User '{req.username}' already exists")
        raise HTTPException(status_code=400, detail="User already exists")

    # 2) Validate all Base64 fields upfront
    try:
        salt = validate_base64(req.salt, "salt")
        public_key = validate_base64(req.public_key, "public_key")
        encrypted_privkey = validate_base64(req.encrypted_privkey, "encrypted_privkey")
        privkey_nonce = validate_base64(req.privkey_nonce, "privkey_nonce")
        encrypted_kek = validate_base64(req.encrypted_kek, "encrypted_kek")
        kek_nonce = validate_base64(req.kek_nonce, "kek_nonce")
        identity_key = validate_base64(req.identity_key, "identity_key")
        signed_pre_key = validate_base64(req.signed_pre_key, "signed_pre_key")
        signed_pre_key_sig = validate_base64(req.signed_pre_key_sig, "signed_pre_key_sig")

        opk_bytes = []
        for i, opk in enumerate(req.one_time_pre_keys):
            opk_bytes.append(validate_base64(opk, f"one_time_pre_key[{i}]"))
    except HTTPException as e:
        raise e
    except Exception as e:
        logging.error(f"Unexpected error during Base64 validation: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error during validation")

    # 3) create the user row
    user_id = db.add_user(
        req.username,
        salt,
        req.argon2_opslimit,
        req.argon2_memlimit,
        public_key,
        encrypted_privkey,
        privkey_nonce,
        encrypted_kek,
        kek_nonce
    )

    # 4) store their X3DH pre-key bundle
    db.add_pre_key_bundle(
        user_id,
        identity_key,
        signed_pre_key,
        signed_pre_key_sig,
    )

    # 5) store one-time pre-keys with sequential IDs
    opks_with_ids = [(i, opk) for i, opk in enumerate(opk_bytes)]
    db.add_opks(user_id, opks_with_ids)

    # 6) store the initial TOFU backup if provided
    if req.encrypted_backup and req.backup_nonce:
        try:
            db.add_tofu_backup(
                user_id,
                base64.b64decode(req.encrypted_backup),
                base64.b64decode(req.backup_nonce)
            )
        except Exception as e:
            logging.error(f"Failed to store initial TOFU backup for user_id={user_id}: {e}")
            # Continue signup even if TOFU backup fails

    logging.info(f"Signup successful (keys + initial TOFU backup stored) for '{req.username}'")
    return {"status": "ok"}

# --- AUTHENTICATE (LOGIN COMPLETE) --------------------------------------
def authenticate_handler(req: AuthenticateRequest, db: models.UserDB):
    logging.debug(f"Authenticate: {req.model_dump_json()}")
    user = db.get_user(req.username)
    if not user:
        logging.warning(f"Unknown user '{req.username}' at authenticate")
        raise HTTPException(status_code=400, detail="Invalid credentials")

    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(user_id, "login")
    if stored is None or provided != stored:
        logging.warning(f"No valid pending challenge for user_id={user_id} (login)")
        raise HTTPException(status_code=400, detail="Invalid credentials")

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
        raise HTTPException(status_code=400, detail="Invalid credentials")

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

    # Validate filename
    if not validate_filename(req.filename):
        logging.warning(f"Invalid filename '{req.filename}' attempted upload")
        raise HTTPException(status_code=400, detail="Invalid filename format")

    user = db.get_user(req.username)
    if not user:
        logging.warning(f"Unknown user '{req.username}' at upload_file")
        raise HTTPException(status_code=404, detail="Unknown user")

    user_id = user["user_id"]

    # Validate Base64 inputs
    try:
        provided       = validate_base64(req.nonce, "nonce")
        encrypted_dek  = validate_base64(req.encrypted_dek, "encrypted_dek")
        signature      = validate_base64(req.signature, "signature")
        encrypted_file = validate_base64(req.encrypted_file, "encrypted_file")
        file_nonce     = validate_base64(req.file_nonce, "file_nonce")
        dek_nonce      = validate_base64(req.dek_nonce, "dek_nonce")
    except HTTPException as e:
        raise e
    except Exception as e:
        logging.error(f"Unexpected error during Base64 validation: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error during validation")

    stored = db.get_pending_challenge(user_id, "upload_file")
    if stored is None or provided != stored:
        logging.warning(f"No valid pending challenge for user_id={user_id} (upload_file)")
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, encrypted_dek)
        db.add_file(
            req.username,
            req.filename,
            encrypted_file,
            file_nonce,
            encrypted_dek,
            dek_nonce
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
        # Signature over the file_id ASCII
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, str(req.file_id).encode())

        record = db.get_file_by_id(req.file_id)
        if not record or record["owner_id"] != user_id:
            logging.warning(f"File ID {req.file_id} not found or not owned by user_id={user_id}")
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

# --- RETRIEVE FILE DEK --------------------------------------------------
def retrieve_file_dek_handler(req: RetrieveFileDEKRequest, db: models.UserDB):
    logging.debug(f"RetrieveFileDEK: {req.model_dump_json()}")
    user = db.get_user(req.username)
    if not user:
        logging.warning(f"Unknown user '{req.username}' at retrieve_file_dek")
        raise HTTPException(status_code=404, detail="Unknown user")

    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(user_id, "retrieve_file_dek")
    if stored is None or provided != stored:
        logging.warning(f"No valid pending challenge for user_id={user_id} (retrieve_file_dek)")
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, provided)

        owner = db.get_file_owner(req.file_id)
        if not owner:
            logging.warning(f"File {req.file_id} not found")
            raise HTTPException(status_code=404, detail="File not found")

        if owner != user_id:
            logging.warning(f"File {req.file_id} not owned by user {user_id}")
            raise HTTPException(status_code=404, detail="File not found")

        dek_data = db.retrieve_file_dek(req.file_id)
        if not dek_data:
            logging.warning(f"No DEK found for file_id={req.file_id}")
            raise HTTPException(status_code=404, detail="DEK not found")

        db.delete_challenge(user_id)
        return {
            "status": "ok",
            "encrypted_dek": base64.b64encode(dek_data['encrypted_dek']).decode(),
            "dek_nonce": base64.b64encode(dek_data['dek_nonce']).decode()
        }
    except InvalidSignature:
        logging.warning(f"Bad signature for retrieve_file_dek of user_id={user_id}")
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
        # Signature over file_id ASCII
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, str(req.file_id).encode())

        db.delete_file_by_id(req.file_id, req.username)
        logging.info(f"File ID '{req.file_id}' deleted for user_id={user_id}")
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
def get_prekey_bundle_handler(req: GetPreKeyBundleRequest, db: models.UserDB):
    logging.debug(f"GetPreKeyBundle: {req.model_dump_json()}")

    # Verify requester's challenge
    requester = db.get_user(req.username)
    if not requester:
        logging.warning(f"Unknown requester '{req.username}' at get_pre_key_bundle")
        raise HTTPException(status_code=404, detail="Unknown requester")

    requester_id = requester["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(requester_id, "get_pre_key_bundle")
    logging.debug(f"Challenge - requester_id={requester_id}, operation=get_pre_key_bundle")
    logging.debug(f"Provided nonce: {base64.b64encode(provided).decode()}")
    logging.debug(f"Stored challenge: {base64.b64encode(stored).decode() if stored else 'None'}")

    if stored is None or provided != stored:
        logging.warning(f"No valid challenge for requester_id={requester_id} (get_pre_key_bundle)")
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(requester["public_key"]) \
            .verify(signature, provided)

        target = db.get_user(req.target_username)
        if not target:
            logging.warning(f"Unknown target user '{req.target_username}' at get_pre_key_bundle")
            raise HTTPException(status_code=404, detail="Target user not found")

        target_id = target["user_id"]
        bundle = db.get_pre_key_bundle(target_id)
        if not bundle:
            raise HTTPException(status_code=404, detail="No prekey bundle found for target user")

        # bundle is a dict: {"IK_pub": ..., "SPK_pub": ..., "SPK_signature": ...}
        return {
            "status": "ok",
            "prekey_bundle": {
                "IK_pub": base64.b64encode(bundle["IK_pub"]).decode(),
                "SPK_pub": base64.b64encode(bundle["SPK_pub"]).decode(),
                "SPK_signature": base64.b64encode(bundle["SPK_signature"]).decode()
            }
        }
    except InvalidSignature:
        db.delete_challenge(requester_id)
        raise HTTPException(status_code=401, detail="Bad signature")

def add_prekey_bundle_handler(req: AddPreKeyBundleRequest, db: models.UserDB):
    logging.debug(f"AddPreKeyBundle: {req.model_dump_json()}")
    user = db.get_user(req.username)
    if not user:
        raise HTTPException(status_code=404, detail="Unknown user")

    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(user_id, "add_pre_key_bundle")
    if stored is None or provided != stored:
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, provided)

        try:
            IK_pub = base64.b64decode(req.IK_pub)
            SPK_pub = base64.b64decode(req.SPK_pub)
            SPK_signature = base64.b64decode(req.SPK_signature)

            highest_opk_id = db.get_highest_opk_id(user_id)
            opks_with_ids = [
                (highest_opk_id + i + 1, key)
                for i, key in enumerate([IK_pub, SPK_pub, SPK_signature])
            ]
            db.add_opks(user_id, opks_with_ids)
            db.delete_challenge(user_id)
            return {"status": "ok", "message": "Prekey bundle added"}
        except Exception as e:
            logging.error(f"Error processing prekey bundle data: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Error processing prekey bundle data: {str(e)}")
    except InvalidSignature:
        db.delete_challenge(user_id)
        raise HTTPException(status_code=401, detail="Bad signature")

def list_users_handler(req: ListUsersRequest, db: models.UserDB) -> ListUsersResponse:
    logging.debug(f"ListUsers: {req.model_dump_json()}")
    user = db.get_user(req.username)
    if not user:
        logging.warning(f"Unknown user '{req.username}' at list_users")
        raise HTTPException(status_code=404, detail="Unknown user")

    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(user_id, "list_users")
    if stored is None or provided != stored:
        logging.warning(f"No valid challenge for user_id={user_id} (list_users)")
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, provided)

        users = db.get_all_users()
        db.delete_challenge(user_id)
        return ListUsersResponse(
            status="ok",
            users=[
                UserData(
                    id=u["id"] if isinstance(u, dict) else u[0],
                    username=u["username"] if isinstance(u, dict) else u[1]
                )
                for u in users
            ]
        )
    except InvalidSignature:
        logging.warning(f"Bad signature for list_users of user_id={user_id}")
        db.delete_challenge(user_id)
        raise HTTPException(status_code=401, detail="Bad signature")

def add_opks_handler(req: AddOPKsRequest, db: models.UserDB):
    logging.debug(f"AddOPKs: {req.model_dump_json()}")
    user = db.get_user(req.username)
    if not user:
        raise HTTPException(status_code=404, detail="Unknown user")

    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(user_id, "add_opks")
    if stored is None or provided != stored:
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, provided)

        try:
            pre_keys = [base64.b64decode(o) for o in req.opks]
            highest_opk_id = db.get_highest_opk_id(user_id)
            opks_with_ids = [
                (highest_opk_id + i + 1, key)
                for i, key in enumerate(pre_keys)
            ]
            db.add_opks(user_id, opks_with_ids)
            db.delete_challenge(user_id)
            return {"status": "ok", "message": "OPKs added"}
        except Exception as e:
            logging.error(f"Error processing OPKs data: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Error processing OPKs data: {str(e)}")
    except InvalidSignature:
        db.delete_challenge(user_id)
        raise HTTPException(status_code=401, detail="Bad signature")

def share_file_handler(req: ShareFileRequest, db: models.UserDB):
    # 1) verify owner & challenge
    user = db.get_user(req.username)
    if not user:
        raise HTTPException(status_code=404, detail="Unknown user")

    uid = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(uid, "share_file")
    if stored is None or provided != stored:
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    # 2) verify signature over encrypted_file_key
    try:
        sig = base64.b64decode(req.signature)
        payload = base64.b64decode(req.encrypted_file_key)
        Ed25519PublicKey.from_public_bytes(user["public_key"]).verify(sig, payload)
    except InvalidSignature:
        db.delete_challenge(uid)
        raise HTTPException(status_code=401, detail="Bad signature")

    # 3) lookup file and recipient
    recipient = db.get_user(req.recipient_username)
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")

    rid = recipient["user_id"]

    # 4) record the share
    try:
        encrypted_file_key = payload
        file_key_nonce     = base64.b64decode(req.file_key_nonce)
        EK_pub            = base64.b64decode(req.EK_pub)
        IK_pub            = base64.b64decode(req.IK_pub)
        SPK_pub           = base64.b64decode(req.SPK_pub)
        SPK_signature     = base64.b64decode(req.SPK_signature)
        OPK_id            = req.OPK_ID if hasattr(req, 'OPK_ID') else None

        db.share_file(
            file_id=req.file_id,
            recipient_id=rid,
            encrypted_file_key=encrypted_file_key,
            file_key_nonce=file_key_nonce,
            EK_pub=EK_pub,
            IK_pub=IK_pub,
            SPK_pub=SPK_pub,
            SPK_signature=SPK_signature,
            OPK_id=OPK_id
        )
        db.delete_challenge(uid)
        return {"status": "ok"}
    except Exception as e:
        logging.error(f"Error sharing file: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error sharing file: {str(e)}")

# ─── LIST ALL SHARES TO ME ───────────────────────────────────────────────
def list_shared_files_handler(req: ListSharedFilesRequest, db: models.UserDB) -> dict:
    """
    List all files shared with the given user.
    Verifies the signature over the raw nonce.
    """
    if not verify_signature(req.username, req.nonce, req.signature):
        raise HTTPException(status_code=401, detail="Invalid challenge signature")

    shared_files = db.get_shared_files(req.username)
    files = []
    for share in shared_files:
        # share is a dict with keys ["share_id","id","filename","shared_by","created_at"]
        files.append({
            "id": share["id"],
            "share_id": share["share_id"],
            "filename": share["filename"],
            "shared_by": share["shared_by"],
            "created_at": share["created_at"]
        })

    return {"status": "ok", "files": files}

def list_shared_to_handler(req: ListSharedToRequest, db: models.UserDB):
    # 1) Verify user & challenge
    user = db.get_user(req.username)
    if not user:
        raise HTTPException(status_code=404, detail="Unknown user")

    uid = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored   = db.get_pending_challenge(uid, "list_shared_to")
    if stored is None or provided != stored:
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    try:
        sig = base64.b64decode(req.signature)
        Ed25519PublicKey.from_public_bytes(user["public_key"]).verify(sig, provided)
    except InvalidSignature:
        db.delete_challenge(uid)
        raise HTTPException(status_code=401, detail="Bad signature")

    # 2) Get target user
    target = db.get_user(req.target_username)
    if not target:
        raise HTTPException(status_code=404, detail="Target user not found")

    # 3) Fetch what I (owner=uid) have shared to target["user_id"]
    rows = db.get_shared_files_to(uid, target["user_id"])
    db.delete_challenge(uid)

    shares = []
    for r in rows:
        # r is a dict: keys ["share_id","file_id","filename","EK_pub","IK_pub","encrypted_file_key","shared_at"]
        share_id = r["share_id"]
        file_id  = r["file_id"]
        filename = r["filename"]
        EK_bytes = r["EK_pub"]
        IK_bytes = r["IK_pub"]
        shared_at = r["shared_at"]
        shares.append(
            SharedFileResponse(
                share_id = share_id,
                file_id  = file_id,
                filename = filename,
                EK_pub   = base64.b64encode(EK_bytes).decode(),
                IK_pub   = base64.b64encode(IK_bytes).decode(),
                shared_at = shared_at.isoformat()
            )
        )

    return {"status": "ok", "shares": shares}

# ─── LIST SHARES SENT TO ME FROM A SPECIFIC USER ────────────────────────
def list_shared_from_handler(req: ListSharedFromRequest, db: models.UserDB):
    user = db.get_user(req.username)
    if not user:
        raise HTTPException(status_code=404, detail="Unknown user")

    uid = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(uid, "list_shared_from")
    if stored is None or provided != stored:
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    try:
        sig = base64.b64decode(req.signature)
        Ed25519PublicKey.from_public_bytes(user["public_key"]).verify(sig, provided)
    except InvalidSignature:
        db.delete_challenge(uid)
        raise HTTPException(status_code=401, detail="Bad signature")

    target = db.get_user(req.target_username)
    if not target:
        raise HTTPException(status_code=404, detail="Target user not found")

    rows = db.get_shared_files_from(uid, target["user_id"])
    db.delete_challenge(uid)

    shares = []
    for r in rows:
        # r is a dict: ["share_id","file_id","filename","EK_pub","IK_pub","encrypted_file_key","shared_at"]
        share_id = r["share_id"]
        file_id  = r["file_id"]
        filename = r["filename"]
        EK_bytes = r["EK_pub"]
        IK_bytes = r["IK_pub"]
        shared_at = r["shared_at"]
        shares.append(
            SharedFileResponse(
                share_id = share_id,
                file_id  = file_id,
                filename = filename,
                EK_pub   = base64.b64encode(EK_bytes).decode(),
                IK_pub   = base64.b64encode(IK_bytes).decode(),
                shared_at = shared_at.isoformat()
            )
        )

    return {"status": "ok", "shares": shares}

# ─── REMOVE A SHARE ────────────────────────────────────────────────────
def remove_shared_file_handler(req: RemoveSharedFileRequest, db: models.UserDB):
    user = db.get_user(req.username)
    if not user:
        raise HTTPException(status_code=404, detail="Unknown user")

    uid = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(uid, "remove_shared_file")
    if stored is None or provided != stored:
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    try:
        sig = base64.b64decode(req.signature)
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(sig, str(req.share_id).encode())
    except InvalidSignature:
        db.delete_challenge(uid)
        raise HTTPException(status_code=401, detail="Bad signature")

    shared_file = db.get_shared_file_details(req.share_id)
    if not shared_file:
        db.delete_challenge(uid)
        raise HTTPException(status_code=404, detail="Shared file not found")

    file_owner_id = db.get_file_owner(shared_file["file_id"])
    if not file_owner_id:
        db.delete_challenge(uid)
        raise HTTPException(status_code=404, detail="File owner not found")

    if uid != file_owner_id and uid != shared_file["recipient_id"]:
        db.delete_challenge(uid)
        raise HTTPException(status_code=403, detail="Not authorized to remove this share")

    db.remove_shared_file(req.share_id)
    db.delete_challenge(uid)
    return {"status": "ok", "message": "share removed"}

def get_opk_handler(req: GetOPKRequest, db: models.UserDB):
    # 1) lookup target user
    target_user = db.get_user(req.target_username)
    if not target_user:
        raise HTTPException(status_code=404, detail="Target user not found")
    target_user_id = target_user["user_id"]

    # 2) lookup requesting user
    requesting_user = db.get_user(req.username)
    if not requesting_user:
        raise HTTPException(status_code=404, detail="Requesting user not found")

    # 3) verify challenge
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(requesting_user["user_id"], "get_opk")
    if stored is None or provided != stored:
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    # 4) verify signature
    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(requesting_user["public_key"])\
            .verify(signature, provided)
    except InvalidSignature:
        db.delete_challenge(requesting_user["user_id"])
        raise HTTPException(status_code=401, detail="Bad signature")

    # 5) fetch & consume one-time pre-key
    opk = db.get_unused_opk(target_user_id)
    if not opk:
        db.delete_challenge(requesting_user["user_id"])
        raise HTTPException(status_code=404, detail="No OPK available")

    db.mark_opk_consumed(opk["id"])

    # 6) return
    db.delete_challenge(requesting_user["user_id"])
    return OPKResponse(
        opk_id=opk["opk_id"],
        pre_key=base64.b64encode(opk["pre_key"]).decode()
    )

def download_shared_file_handler(req: DownloadSharedFileRequest, db: models.UserDB):
    # 1) verify owner & challenge
    user = db.get_user(req.username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(user_id, "download_shared_file")
    if stored is None or provided != stored:
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    # 2) Verify signature
    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, str(req.share_id).encode())
    except InvalidSignature:
        db.delete_challenge(user_id)
        raise HTTPException(status_code=401, detail="Bad signature")

    # 3) Get the shared file data
    shared_file = db.get_shared_file(req.share_id, user_id)
    if not shared_file:
        raise HTTPException(status_code=404, detail="Shared file not found")

    # 4) Get original file's nonce
    file_nonce = db.get_file_nonce(shared_file["file_id"])
    if not file_nonce:
        raise HTTPException(status_code=404, detail="File nonce not found")

    return {
        "status": "ok",
        "encrypted_file": base64.b64encode(shared_file["encrypted_file"]).decode(),
        "file_nonce": base64.b64encode(file_nonce).decode(),
        "encrypted_file_key": base64.b64encode(shared_file["encrypted_file_key"]).decode(),
        "file_key_nonce": base64.b64encode(shared_file["file_key_nonce"]).decode(),
        "EK_pub": base64.b64encode(shared_file["EK_pub"]).decode(),
        "IK_pub": base64.b64encode(shared_file["IK_pub"]).decode(),
        "SPK_pub": base64.b64encode(shared_file["SPK_pub"]).decode(),
        "SPK_signature": base64.b64encode(shared_file["SPK_signature"]).decode(),
        "opk_id": shared_file["OPK_id"]
    }

def list_matching_users_handler(req: ListMatchingUsersRequest, db: models.UserDB) -> ListUsersResponse:
    logging.debug(f"ListMatchingUsers: {req.model_dump_json()}")
    user = db.get_user(req.username)
    if not user:
        logging.warning(f"Unknown user '{req.username}' at list_matching_users")
        raise HTTPException(status_code=404, detail="Unknown user")

    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(user_id, "list_matching_users")
    if stored is None or provided != stored:
        logging.warning(f"No valid challenge for user_id={user_id} (list_matching_users)")
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, provided)

        users = db.get_matching_users(req.search_query)
        db.delete_challenge(user_id)
        return ListUsersResponse(
            status="ok",
            users=[
                UserData(
                    id=u["id"] if isinstance(u, dict) else u[0],
                    username=u["username"] if isinstance(u, dict) else u[1]
                )
                for u in users
            ]
        )
    except InvalidSignature:
        logging.warning(f"Bad signature for list_matching_users of user_id={user_id}")
        db.delete_challenge(user_id)
        raise HTTPException(status_code=401, detail="Bad signature")

# ─── LIST ALL DISTINCT USERS WHO SHARED TO A TARGET ─────────────────────────
def list_sharers_handler(req: ListSharersRequest, db: models.UserDB) -> dict:
    """
    Return distinct usernames who have shared at least one file to req.username.
    """
    user = db.get_user(req.username)
    if not user:
        raise HTTPException(status_code=404, detail="Unknown user")
    uid = user["user_id"]

    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(uid, "list_sharers")
    if stored is None or provided != stored:
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    try:
        sig = base64.b64decode(req.signature)
        Ed25519PublicKey.from_public_bytes(user["public_key"]).verify(sig, provided)
    except InvalidSignature:
        db.delete_challenge(uid)
        raise HTTPException(status_code=401, detail="Bad signature")

    sharers = db.get_sharers(uid)
    db.delete_challenge(uid)
    return {
        "status": "ok",
        "usernames": sharers
    }

# ─── TEST ENDPOINT: CLEAR USER'S OPKs ───────────────────────────────────
def clear_user_opks_handler(req: ClearUserOPKsRequest, db: models.UserDB) -> dict:
    """
    Test endpoint to clear all OPKs for a user.
    This is for testing X3DH without OPKs.
    """
    # Verify the requesting user
    user = db.get_user(req.username)
    if not user:
        raise HTTPException(status_code=404, detail="Unknown requesting user")
    uid = user["user_id"]

    # Get the target user
    target = db.get_user(req.target_username)
    if not target:
        raise HTTPException(status_code=404, detail="Target user not found")
    target_id = target["user_id"]

    # Verify the challenge and signature
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(uid, "clear_user_opks")
    if stored is None or provided != stored:
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    try:
        sig = base64.b64decode(req.signature)
        Ed25519PublicKey.from_public_bytes(user["public_key"]).verify(sig, provided)
    except InvalidSignature:
        db.delete_challenge(uid)
        raise HTTPException(status_code=401, detail="Bad signature")

    # Clear all OPKs for the target user
    db.clear_user_opks(target_id)
    db.delete_challenge(uid)
    return {
        "status": "ok",
        "message": f"Cleared all OPKs for user {req.target_username}"
    }

