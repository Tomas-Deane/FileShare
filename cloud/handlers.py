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
    PreKeyBundleRequest,
    GetOPKRequest,
    ShareFileRequest,
    RemoveSharedFileRequest,
    ListSharedFilesRequest,
    AddOPKsRequest,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

import models

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

    # Add the user first
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

    # Add the pre-key bundle
    db.add_pre_key_bundle(user_id,
        base64.b64decode(req.identity_key),
        base64.b64decode(req.signed_pre_key), 
        base64.b64decode(req.signed_pre_key_sig)
    )

    # Add the one-time pre-keys
    pre_keys = [base64.b64decode(pk) for pk in req.one_time_pre_keys]
    db.add_opks(user_id, pre_keys)

    logging.info(f"Signup successful for '{req.username}' with {len(pre_keys)} OPKs")
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

# --- PREKEY BUNDLE ------------------------------------------------------
def prekey_bundle_handler(req: PreKeyBundleRequest, db: models.UserDB):
    logging.debug(f"PreKeyBundle: {req.model_dump_json()}")
    user = db.get_user(req.username)
    if not user:
        logging.warning(f"Unknown user '{req.username}' at prekey_bundle")
        raise HTTPException(status_code=404, detail="Unknown user")

    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(user_id, "prekey_bundle")
    if stored is None or provided != stored:
        logging.warning(f"No valid pending challenge for user_id={user_id} (prekey_bundle)")
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, provided)
        
        bundle = db.get_pre_key_bundle(user_id)
        if not bundle:
            raise HTTPException(status_code=404, detail="No prekey bundle found")
            
        db.delete_challenge(user_id)
        return {
            "status": "ok",
            "IK_pub": base64.b64encode(bundle["IK_pub"]).decode(),
            "SPK_pub": base64.b64encode(bundle["SPK_pub"]).decode(),
            "SPK_signature": base64.b64encode(bundle["SPK_signature"]).decode()
        }
    except InvalidSignature:
        logging.warning(f"Bad signature for prekey_bundle of user_id={user_id}")
        db.delete_challenge(user_id)
        raise HTTPException(status_code=401, detail="Bad signature")

# --- ADD PREKEY BUNDLE -------------------------------------------------- 
def add_prekey_bundle_handler(req: PreKeyBundleRequest, db: models.UserDB):
    logging.debug(f"Add PreKeyBundle: {req.model_dump_json()}")
    user = db.get_user(req.username)
    if not user:
        logging.warning(f"Unknown user '{req.username}' at add_prekey_bundle")
        raise HTTPException(status_code=404, detail="Unknown user")

    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(user_id, "add_prekey_bundle")
    if stored is None or provided != stored:
        logging.warning(f"No valid pending challenge for user_id={user_id} (add_prekey_bundle)")
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, provided)

        db.add_pre_key_bundle(user_id, 
            base64.b64decode(req.IK_pub),
            base64.b64decode(req.SPK_pub),
            base64.b64decode(req.SPK_signature))
            
        db.delete_challenge(user_id)
        return {
            "status": "ok",
            "message": "PreKey bundle added successfully"
        }
    except InvalidSignature:
        logging.warning(f"Bad signature for add_prekey_bundle of user_id={user_id}")
        db.delete_challenge(user_id)
        raise HTTPException(status_code=401, detail="Bad signature")

# --- GET OPK ------------------------------------------------------
def opk_handler(req: GetOPKRequest, db: models.UserDB):
    logging.debug(f"GetOPK: {req.model_dump_json()}")
    user = db.get_user(req.username)
    if not user:
        logging.warning(f"Unknown user '{req.username}' at get_opk")
        raise HTTPException(status_code=404, detail="Unknown user")

    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(user_id, "get_opk")
    if stored is None or provided != stored:
        logging.warning(f"No valid pending challenge for user_id={user_id} (get_opk)")
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, provided)
        
        opk = db.get_unused_opk(user_id)
        if not opk:
            raise HTTPException(status_code=404, detail="No unused OPKs available")
            
        db.mark_opk_consumed(opk["id"])
        db.delete_challenge(user_id)
        return {
            "status": "ok",
            "opk_id": opk["id"],
            "pre_key": base64.b64encode(opk["pre_key"]).decode()
        }
    except InvalidSignature:
        logging.warning(f"Bad signature for get_opk of user_id={user_id}")
        db.delete_challenge(user_id)
        raise HTTPException(status_code=401, detail="Bad signature")
    
# --- ADD OPKS ------------------------------------------------------
def add_opks_handler(req: AddOPKsRequest, db: models.UserDB):
    logging.debug(f"AddOPKs: {req.model_dump_json()}")
    user = db.get_user(req.username)
    if not user:
        logging.warning(f"Unknown user '{req.username}' at add_opks")
        raise HTTPException(status_code=404, detail="Unknown user")

    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(user_id, "add_opks")
    if stored is None or provided != stored:
        logging.warning(f"No valid pending challenge for user_id={user_id} (add_opks)")
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, provided)
        
        # Decode all pre-keys from base64
        pre_keys = [base64.b64decode(pk) for pk in req.pre_keys]
        
        # Add the pre-keys to the database
        db.add_opks(user_id, pre_keys)
        
        db.delete_challenge(user_id)
        return {"status": "ok", "message": f"Added {len(pre_keys)} OPKs"}
    except InvalidSignature:
        logging.warning(f"Bad signature for add_opks of user_id={user_id}")
        db.delete_challenge(user_id)
        raise HTTPException(status_code=401, detail="Bad signature")
    
# --- SHARE FILE ------------------------------------------------------
def share_file_handler(req: ShareFileRequest, db: models.UserDB):
    logging.debug(f"ShareFile: {req.model_dump_json()}")
    user = db.get_user(req.username)
    if not user:
        logging.warning(f"Unknown user '{req.username}' at share_file")
        raise HTTPException(status_code=404, detail="Unknown user")

    recipient = db.get_user(req.recipient_username)
    if not recipient:
        logging.warning(f"Unknown recipient '{req.recipient_username}' at share_file")
        raise HTTPException(status_code=404, detail="Unknown recipient")

    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(user_id, "share_file")
    if stored is None or provided != stored:
        logging.warning(f"No valid pending challenge for user_id={user_id} (share_file)")
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, req.filename.encode())
        
        # Get file_id for the file being shared
        file_record = db.get_file(req.username, req.filename)
        if not file_record:
            raise HTTPException(status_code=404, detail="File not found")
            
        db.share_file(
            file_record["id"],
            recipient["user_id"],
            base64.b64decode(req.EK_pub),
            base64.b64decode(req.IK_pub)
        )
        
        db.delete_challenge(user_id)
        return {"status": "ok", "message": "file shared"}
    except InvalidSignature:
        logging.warning(f"Bad signature for share_file of user_id={user_id}")
        db.delete_challenge(user_id)
        raise HTTPException(status_code=401, detail="Bad signature")

# --- REMOVE SHARED FILE ------------------------------------------------------
def remove_shared_file_handler(req: RemoveSharedFileRequest, db: models.UserDB):
    logging.debug(f"RemoveSharedFile: {req.model_dump_json()}")
    user = db.get_user(req.username)
    if not user:
        logging.warning(f"Unknown user '{req.username}' at remove_shared_file")
        raise HTTPException(status_code=404, detail="Unknown user")

    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(user_id, "remove_shared_file")
    if stored is None or provided != stored:
        logging.warning(f"No valid pending challenge for user_id={user_id} (remove_shared_file)")
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, str(req.share_id).encode())
        
        # Verify the user has permission to remove this share
        share = db.get_shared_file_details(req.share_id)
        if not share:
            raise HTTPException(status_code=404, detail="Share not found")
            
        # Only the file owner can remove shares
        file_record = db.get_file(req.username, share["filename"])
        if not file_record:
            raise HTTPException(status_code=403, detail="Not authorized to remove this share")
            
        db.remove_shared_file(req.share_id)
        db.delete_challenge(user_id)
        return {"status": "ok", "message": "share removed"}
    except InvalidSignature:
        logging.warning(f"Bad signature for remove_shared_file of user_id={user_id}")
        db.delete_challenge(user_id)
        raise HTTPException(status_code=401, detail="Bad signature")

# --- LIST SHARED FILES ------------------------------------------------------
def list_shared_files_handler(req: ListSharedFilesRequest, db: models.UserDB):
    logging.debug(f"ListSharedFiles: {req.model_dump_json()}")
    user = db.get_user(req.username)
    if not user:
        logging.warning(f"Unknown user '{req.username}' at list_shared_files")
        raise HTTPException(status_code=404, detail="Unknown user")

    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(user_id, "list_shared_files")
    if stored is None or provided != stored:
        logging.warning(f"No valid pending challenge for user_id={user_id} (list_shared_files)")
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, provided)
        
        shared_files = db.get_shared_files(user_id)
        db.delete_challenge(user_id)
        return {
            "status": "ok",
            "files": [{
                "share_id": f["share_id"],
                "file_id": f["file_id"],
                "filename": f["filename"],
                "EK_pub": base64.b64encode(f["EK_pub"]).decode(),
                "IK_pub": base64.b64encode(f["IK_pub"]).decode(),
                "shared_at": f["shared_at"].isoformat()
            } for f in shared_files]
        }
    except InvalidSignature:
        logging.warning(f"Bad signature for list_shared_files of user_id={user_id}")
        db.delete_challenge(user_id)
        raise HTTPException(status_code=401, detail="Bad signature")

