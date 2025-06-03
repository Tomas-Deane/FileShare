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
    PreviewSharedFileRequest,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
import datetime

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
        raise HTTPException(status_code=400, detail="Invalid credentials")

    user_id = user["user_id"]
    challenge = secrets.token_bytes(32)
    db.add_challenge(user_id, req.operation, challenge)
    logging.debug(f"Stored challenge for user_id={user_id} op={req.operation}: {base64.b64encode(challenge).decode()}")
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

    # 2) create the user row in `users` + `username_map`
    user_id = db.add_user(
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

    # 3) store their X3DH pre-key bundle (identity key, signed pre-key, signature)
    db.add_pre_key_bundle(
        user_id,
        base64.b64decode(req.identity_key),
        base64.b64decode(req.signed_pre_key),
        base64.b64decode(req.signed_pre_key_sig),
    )

    # 4) store their one-time pre-keys
    opk_bytes = [base64.b64decode(k) for k in req.one_time_pre_keys]
    # Create list of tuples with sequential opk_ids (0 to len-1)
    opks_with_ids = [(i, opk) for i, opk in enumerate(opk_bytes)]
    db.add_opks(user_id, opks_with_ids)
    
    # 5) store the very first TOFU backup (if provided)
    #    We expect the client to have encrypted their "newly‐generated identity+prekeys"
    #    under the session‐Kek, and sent us base64 ciphertext + base64 nonce.
    if req.encrypted_backup and req.backup_nonce:
        try:
            db.add_tofu_backup(
                user_id,
                base64.b64decode(req.encrypted_backup),
                base64.b64decode(req.backup_nonce)
            )
        except Exception as e:
            logging.error(f"Failed to store initial TOFU backup for user_id={user_id}: {e}")
            # We allow signup to succeed, but log the failure.
            # Alternatively, you could reject signup by raising HTTPException here.

    logging.info(f"Signup successful (and X3DH keys + initial TOFU backup stored) for '{req.username}'")
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
        
        # First check if the file exists
        file_owner = db.get_file_owner(req.file_id)
        if not file_owner:
            logging.warning(f"File {req.file_id} not found")
            raise HTTPException(status_code=404, detail="File not found")
            
        # Then verify ownership
        if file_owner != user_id:
            logging.warning(f"File {req.file_id} not owned by user {user_id}")
            raise HTTPException(status_code=404, detail="File not found")
        
        # Get the DEK directly using file_id
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
def get_prekey_bundle_handler(req: GetPreKeyBundleRequest, db: models.UserDB):
    logging.debug(f"GetPreKeyBundle: {req.model_dump_json()}")
    
    # First verify the requesting user and their challenge
    requester = db.get_user(req.username)
    if not requester:
        logging.warning(f"Unknown requester '{req.username}' at get_pre_key_bundle")
        raise HTTPException(status_code=404, detail="Unknown requester")
    
    requester_id = requester["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(requester_id, "get_pre_key_bundle")
    logging.debug(f"Challenge verification - Requester ID: {requester_id}, Operation: get_pre_key_bundle")
    logging.debug(f"Provided nonce: {base64.b64encode(provided).decode()}")
    logging.debug(f"Stored challenge: {base64.b64encode(stored).decode() if stored else 'None'}")
    
    if stored is None or provided != stored:
        logging.warning(f"No valid pending challenge for requester_id={requester_id} (get_pre_key_bundle)")
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")
    
    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(requester["public_key"]) \
            .verify(signature, provided)
        
        # Now get the target user's prekey bundle
        target = db.get_user(req.target_username)
        if not target:
            logging.warning(f"Unknown target user '{req.target_username}' at get_pre_key_bundle")
            raise HTTPException(status_code=404, detail="Target user not found")
        
        target_id = target["user_id"]
        bundle = db.get_pre_key_bundle(target_id)
        if not bundle:
            raise HTTPException(status_code=404, detail="No prekey bundle found for target user")
        
        # Convert binary data to base64 for response
        return {
            "status": "ok",
            "prekey_bundle": {
                "IK_pub": base64.b64encode(bundle[0]).decode(),  # First element is IK_pub
                "SPK_pub": base64.b64encode(bundle[1]).decode(),  # Second element is SPK_pub
                "SPK_signature": base64.b64encode(bundle[2]).decode()  # Third element is SPK_signature
            }
        }
    except InvalidSignature:
        db.delete_challenge(requester_id)
        raise HTTPException(status_code=401, detail="Bad signature")

#add prekey bundle
def add_prekey_bundle_handler(req: AddPreKeyBundleRequest, db: models.UserDB):
    logging.debug(f"AddPreKeyBundle: {req.model_dump_json()}")
    try:
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
            
            # Decode base64 data before passing to database
            try:
                IK_pub = base64.b64decode(req.IK_pub)
                SPK_pub = base64.b64decode(req.SPK_pub)
                SPK_signature = base64.b64decode(req.SPK_signature)
                
                logging.debug(f"Decoded data lengths - IK_pub: {len(IK_pub)}, SPK_pub: {len(SPK_pub)}, SPK_signature: {len(SPK_signature)}")
                
                # Get the highest existing opk_id for this user
                highest_opk_id = db.get_highest_opk_id(user_id)
                # Create list of tuples with sequential opk_ids starting from highest + 1
                opks_with_ids = [(highest_opk_id + i + 1, opk) for i, opk in enumerate([IK_pub, SPK_pub, SPK_signature])]
                db.add_opks(user_id, opks_with_ids)
                db.delete_challenge(user_id)
                return {"status": "ok", "message": "Prekey bundle added"}
            except Exception as e:
                logging.error(f"Error processing prekey bundle data: {str(e)}")
                raise HTTPException(status_code=500, detail=f"Error processing prekey bundle data: {str(e)}")
        except InvalidSignature:
            db.delete_challenge(user_id)
            raise HTTPException(status_code=401, detail="Bad signature")
    except Exception as e:
        logging.error(f"Unexpected error in add_prekey_bundle_handler: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

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
        
        # Decode base64 data before passing to database
        try:
            pre_keys = [base64.b64decode(opk) for opk in req.opks]
            # Get the highest existing opk_id for this user
            highest_opk_id = db.get_highest_opk_id(user_id)
            # Create list of tuples with sequential opk_ids starting from highest + 1
            opks_with_ids = [(highest_opk_id + i + 1, opk) for i, opk in enumerate(pre_keys)]
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
        raise HTTPException(404, "Unknown user")

    uid = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(uid, "share_file")
    if stored is None or provided != stored:
        raise HTTPException(400, "Invalid or expired challenge")

    # 2) verify signature over the encrypted_file_key
    sig = base64.b64decode(req.signature)
    payload = base64.b64decode(req.encrypted_file_key)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]).verify(sig, payload)
    except Exception:
        db.delete_challenge(uid)
        raise HTTPException(401, "Bad signature")

    # 3) lookup file and recipient
    file_id = req.file_id
    recipient = db.get_user(req.recipient_username)
    if not recipient:
        raise HTTPException(404, "Recipient not found")

    rid = recipient["user_id"]
    efk = payload

    # 4) Use the OPK_ID from the request
    opk_id = req.OPK_ID
    
    # 5) record the share
    try:
        # Convert base64 fields to bytes
        encrypted_file_key = base64.b64decode(req.encrypted_file_key)
        file_key_nonce = base64.b64decode(req.file_key_nonce)
        EK_pub = base64.b64decode(req.EK_pub)
        IK_pub = base64.b64decode(req.IK_pub)
        SPK_pub = base64.b64decode(req.SPK_pub)
        SPK_signature = base64.b64decode(req.SPK_signature)
        
        # Create the shared file record using the correct parameters
        db.share_file(
            file_id=req.file_id,
            recipient_id=recipient["user_id"],
            encrypted_file_key=encrypted_file_key,
            file_key_nonce=file_key_nonce,
            EK_pub=EK_pub,
            IK_pub=IK_pub,
            SPK_pub=SPK_pub,
            SPK_signature=SPK_signature,
            OPK_id=req.OPK_ID
        )
        
        return {"status": "ok"}
        
    except Exception as e:
        logging.error(f"Error sharing file: {str(e)}")
        raise HTTPException(500, f"Error sharing file: {str(e)}")

# ─── LIST ALL SHARES TO ME ───────────────────────────────────────────────
def list_shared_files_handler(req: ListSharedFilesRequest, db: models.UserDB) -> dict:
    """List all files shared with the user."""
    # Verify the challenge
    if not verify_signature(req.username, req.nonce, req.signature):
        raise HTTPException(status_code=401, detail="Invalid challenge signature")

    # Get all files shared with this user
    shared_files = db.get_shared_files(req.username)
    
    # Format the response
    files = []
    for share in shared_files:
        # Unpack the tuple correctly
        share_id, file_id, filename, shared_by, created_at = share
        
        files.append({
            "id": file_id,
            "share_id": share_id,
            "filename": filename,
            "shared_by": shared_by,
            "created_at": created_at
        })

    return {
        "status": "ok",
        "files": files
    }

# ─── LIST SHARES I SENT TO A SPECIFIC USER ──────────────────────────────
def list_shared_to_handler(req: ListSharedToRequest, db: models.UserDB):
    user = db.get_user(req.username)
    if not user:
        raise HTTPException(404, "Unknown user")
    uid = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(uid, "list_shared_to")
    if stored is None or provided != stored:
        raise HTTPException(400, "Invalid or expired challenge")
    sig = base64.b64decode(req.signature)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]).verify(sig, provided)
    except Exception:
        db.delete_challenge(uid)
        raise HTTPException(401, "Bad signature")

    target = db.get_user(req.target_username)
    if not target:
        raise HTTPException(404, "Target user not found")
    rows = db.get_shared_files_to(uid, target["user_id"])
    db.delete_challenge(uid)
    return {"status": "ok", "shares": [
        SharedFileResponse(
            share_id = r["share_id"],
            file_id  = r["file_id"],
            filename = r["filename"],
            EK_pub   = base64.b64encode(r["EK_pub"]).decode(),
            IK_pub   = base64.b64encode(r["IK_pub"]).decode(),
            shared_at= r["shared_at"].isoformat()
        )
        for r in rows
    ]}

# ─── LIST SHARES SENT TO ME FROM A SPECIFIC USER ────────────────────────
def list_shared_from_handler(req: ListSharedFromRequest, db: models.UserDB):
    user = db.get_user(req.username)
    if not user:
        raise HTTPException(404, "Unknown user")
    uid = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(uid, "list_shared_from")
    if stored is None or provided != stored:
        raise HTTPException(400, "Invalid or expired challenge")
    sig = base64.b64decode(req.signature)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]).verify(sig, provided)
    except Exception:
        db.delete_challenge(uid)
        raise HTTPException(401, "Bad signature")

    target = db.get_user(req.target_username)
    if not target:
        raise HTTPException(404, "Target user not found")
    rows = db.get_shared_files_from(uid, target["user_id"])
    db.delete_challenge(uid)
    return {"status": "ok", "shares": [
        SharedFileResponse(
            share_id = r["share_id"],
            file_id  = r["file_id"],
            filename = r["filename"],
            EK_pub   = base64.b64encode(r["EK_pub"]).decode(),
            IK_pub   = base64.b64encode(r["IK_pub"]).decode(),
            shared_at= r["shared_at"].isoformat()
        )
        for r in rows
    ]}

# ─── REMOVE A SHARE ────────────────────────────────────────────────────
def remove_shared_file_handler(req: RemoveSharedFileRequest, db: models.UserDB):
    user = db.get_user(req.username)
    if not user:
        raise HTTPException(404, "Unknown user")
    uid = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(uid, "remove_shared_file")
    if stored is None or provided != stored:
        raise HTTPException(400, "Invalid or expired challenge")
    sig = base64.b64decode(req.signature)
    # verify signature on the share_id itself
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(sig, str(req.share_id).encode())
    except Exception:
        db.delete_challenge(uid)
        raise HTTPException(401, "Bad signature")

    db.remove_shared_file(req.share_id)
    db.delete_challenge(uid)
    return {"status": "ok", "message": "share removed"}

def get_opk_handler(req: GetOPKRequest, db: models.UserDB):
    # 1) lookup target user (the one we want OPK for)
    target_user = db.get_user(req.target_username)  # Add target_username to GetOPKRequest
    if not target_user:
        raise HTTPException(404, "Target user not found")
    target_user_id = target_user["user_id"]

    # 2) lookup requesting user (for signature verification)
    requesting_user = db.get_user(req.username)
    if not requesting_user:
        raise HTTPException(404, "Requesting user not found")
    
    # 3) verify challenge using requesting user's ID
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(requesting_user["user_id"], "get_opk")
    if stored is None or provided != stored:
        raise HTTPException(400, "Invalid or expired challenge")

    # 4) verify signature using requesting user's public key
    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(requesting_user["public_key"])\
            .verify(signature, provided)
    except InvalidSignature:
        db.delete_challenge(requesting_user["user_id"])
        raise HTTPException(401, "Bad signature")

    # 5) fetch & consume one-time pre-key for target user
    opk = db.get_unused_opk(target_user_id)
    if not opk:
        db.delete_challenge(requesting_user["user_id"])
        raise HTTPException(404, "No OPK available")
    
    # Mark the OPK as consumed using its database id
    db.mark_opk_consumed(opk["id"])

    # 6) done—return it
    db.delete_challenge(requesting_user["user_id"])
    return OPKResponse(
        opk_id=opk["opk_id"],  # Return the opk_id (0-99)
        pre_key=base64.b64encode(opk["pre_key"]).decode()
    )

def download_shared_file_handler(req: DownloadSharedFileRequest, db: models.UserDB):
    # 1) verify owner & challenge
    user = db.get_user(req.username)
    if not user:
        raise HTTPException(404, "User not found")
    
    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(user_id, "download_shared_file")
    if stored is None or provided != stored:
        raise HTTPException(400, "Invalid or expired challenge")

    # 2) Verify signature
    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, str(req.share_id).encode())
    except InvalidSignature:
        db.delete_challenge(user_id)
        raise HTTPException(401, "Bad signature")

    # 3) Get the shared file data
    shared_file = db.get_shared_file(req.share_id, user_id)
    if not shared_file:
        raise HTTPException(404, "Shared file not found")

    # Get the original file's nonce
    file_nonce = db.get_file_nonce(shared_file["file_id"])
    if not file_nonce:
        raise HTTPException(404, "File nonce not found")

    # Return both nonces
    return {
        "status": "ok",
        "encrypted_file": base64.b64encode(shared_file["encrypted_file"]).decode(),
        "file_nonce": base64.b64encode(file_nonce).decode(),  # Original file's nonce
        "encrypted_file_key": base64.b64encode(shared_file["encrypted_file_key"]).decode(),
        "file_key_nonce": base64.b64encode(shared_file["file_key_nonce"]).decode(),  # Nonce for decrypting the file key
        "EK_pub": base64.b64encode(shared_file["EK_pub"]).decode(),
        "IK_pub": base64.b64encode(shared_file["IK_pub"]).decode(),
        "SPK_pub": base64.b64encode(shared_file["SPK_pub"]).decode(),
        "SPK_signature": base64.b64encode(shared_file["SPK_signature"]).decode(),
        "opk_id": shared_file["OPK_id"]
    }

def preview_shared_file_handler(req: PreviewSharedFileRequest, db: models.UserDB):
    # 1) verify owner & challenge
    user = db.get_user(req.username)
    if not user:
        raise HTTPException(404, "User not found")
    
    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(user_id, "preview_shared_file")
    if stored is None or provided != stored:
        raise HTTPException(400, "Invalid or expired challenge")

    # 2) Verify signature
    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, str(req.share_id).encode())
    except InvalidSignature:
        db.delete_challenge(user_id)
        raise HTTPException(401, "Bad signature")

    # 3) Get the shared file data
    shared_file = db.get_shared_file(req.share_id, user_id)
    if not shared_file:
        raise HTTPException(404, "Shared file not found")

    # Get the original file's nonce
    file_nonce = db.get_file_nonce(shared_file["file_id"])
    if not file_nonce:
        raise HTTPException(404, "File nonce not found")

    # Return both nonces
    return {
        "status": "ok",
        "encrypted_file": base64.b64encode(shared_file["encrypted_file"]).decode(),
        "file_nonce": base64.b64encode(file_nonce).decode(),  # Original file's nonce
        "encrypted_file_key": base64.b64encode(shared_file["encrypted_file_key"]).decode(),
        "file_key_nonce": base64.b64encode(shared_file["file_key_nonce"]).decode(),  # Nonce for decrypting the file key
        "EK_pub": base64.b64encode(shared_file["EK_pub"]).decode(),
        "IK_pub": base64.b64encode(shared_file["IK_pub"]).decode(),
        "SPK_pub": base64.b64encode(shared_file["SPK_pub"]).decode(),
        "SPK_signature": base64.b64encode(shared_file["SPK_signature"]).decode(),
        "opk_id": shared_file["OPK_id"]
    }

def list_matching_users_handler(req: ListMatchingUsersRequest, db: models.UserDB) -> ListUsersResponse:
    """List all users whose usernames match the given search query."""
    logging.debug(f"ListMatchingUsers: {req.model_dump_json()}")
    
    # Verify the requesting user
    user = db.get_user(req.username)
    if not user:
        logging.warning(f"Unknown user '{req.username}' at list_matching_users")
        raise HTTPException(status_code=404, detail="Unknown user")

    # Verify the challenge
    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(user_id, "list_matching_users")
    if stored is None or provided != stored:
        logging.warning(f"No valid pending challenge for user_id={user_id} (list_matching_users)")
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    # Verify the signature
    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, provided)
        
        # Get matching users
        users = db.get_matching_users(req.search_query)
        
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
        logging.warning(f"Bad signature for list_matching_users of user_id={user_id}")
        db.delete_challenge(user_id)
        raise HTTPException(status_code=401, detail="Bad signature")
