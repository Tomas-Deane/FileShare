# File: cloud/handlers.py
#!/usr/bin/env python3
import base64
import secrets
import logging
from fastapi import HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

import models

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
    operation: str  # e.g. "login", "change_username", "change_password", "upload_file"

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

# --- CHALLENGE HANDLER --------------------------------------------
def challenge_handler(req, db: models.UserDB):
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
def login_handler_continue(req, db: models.UserDB, b64_nonce: str):
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
def signup_handler(req, db: models.UserDB):
    logging.debug(f"Signup: {req.json()}")
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
def authenticate_handler(req, db: models.UserDB):
    logging.debug(f"Authenticate: {req.json()}")
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
def change_username_handler(req, db: models.UserDB):
    logging.debug(f"ChangeUsername: {req.json()}")
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
def change_password_handler(req, db: models.UserDB):
    logging.debug(f"ChangePassword: {req.json()}")
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
    encrypted_kek = base64.b64decode(req.encrypted_kek)
    signature = base64.b64decode(req.signature)
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
def upload_file_handler(req, db: models.UserDB):
    logging.debug(f"UploadRequest: {req.json()}")
    user = db.get_user(req.username)
    if not user:
        logging.warning(f"Unknown user '{req.username}' at upload_file")
        raise HTTPException(status_code=404, detail="Unknown user")

    user_id = user["user_id"]
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(user_id, "upload_file")
    if stored is None or provided != stored:
        logging.warning(f"No valid pending challenge for user_id={user_id} (upload_file)")
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    encrypted_dek = base64.b64decode(req.encrypted_dek)
    signature = base64.b64decode(req.signature)
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

