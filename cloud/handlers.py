#!/usr/bin/env python3
import base64
import secrets
import logging
from fastapi import HTTPException
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

import models

# --- CHALLENGE HANDLER --------------------------------------------
def challenge_handler(req, db: models.UserDB):
    # verify user exists (for all ops)
    if not db.get_user(req.username):
        logging.warning(f"Unknown user '{req.username}' at challenge")
        raise HTTPException(status_code=404, detail="Unknown user")

    # generate and store a fresh 32-byte nonce
    challenge = secrets.token_bytes(32)
    db.add_challenge(req.username, req.operation, challenge)
    logging.debug(f"Stored challenge for '{req.username}' op={req.operation}: {challenge.hex()}")

    return {
        "status": "challenge",
        "nonce": base64.b64encode(challenge).decode()
    }


# --- LOGIN CONTINUATION ------------------------------------------------
def login_handler_continue(req, db: models.UserDB, b64_nonce: str):
    """
    After challenge, return the full login payload (salt / argon2 params / encrypted_privkey / privkey_nonce)
    """
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
        "privkey_nonce": base64.b64encode(user["privkey_nonce"]).decode()
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
        base64.b64decode(req.privkey_nonce)
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

    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(req.username, "login")
    if stored is None:
        logging.warning(f"No valid pending challenge for '{req.username}' (login)")
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    if provided != stored:
        logging.warning(f"Nonce mismatch for '{req.username}' (login)")
        raise HTTPException(status_code=400, detail="Invalid challenge nonce")

    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, provided)
        logging.info(f"Signature valid for '{req.username}' (login)")
        db.delete_challenge(req.username)
        return {"status": "ok", "message": "login successful"}
    except InvalidSignature:
        logging.warning(f"Bad signature for '{req.username}' (login)")
        db.delete_challenge(req.username)
        raise HTTPException(status_code=401, detail="Bad signature")


# --- CHANGE USERNAME ------------------------------------------------------
def change_username_handler(req, db: models.UserDB):
    logging.debug(f"ChangeUsername: {req.json()}")
    user = db.get_user(req.username)
    if not user:
        logging.warning(f"Unknown user '{req.username}' at change_username")
        raise HTTPException(status_code=404, detail="Unknown user")

    # first verify the nonce
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(req.username, "change_username")
    if stored is None or provided != stored:
        logging.warning(f"No valid pending challenge for '{req.username}' (change_username)")
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    # then verify the signature over the new username
    signature = base64.b64decode(req.signature)
    try:
        Ed25519PublicKey.from_public_bytes(user["public_key"]) \
            .verify(signature, req.new_username.encode())
        db.update_username(req.username, req.new_username)
        logging.info(f"Username changed from '{req.username}' to '{req.new_username}'")
        db.delete_challenge(req.username)
        return {"status": "ok", "message": "username changed"}
    except InvalidSignature:
        logging.warning(f"Bad signature for change_username of '{req.username}'")
        db.delete_challenge(req.username)
        raise HTTPException(status_code=401, detail="Bad signature")


# --- CHANGE PASSWORD ------------------------------------------------------
def change_password_handler(req, db: models.UserDB):
    logging.debug(f"ChangePassword: {req.json()}")
    user = db.get_user(req.username)
    if not user:
        logging.warning(f"Unknown user '{req.username}' at change_password")
        raise HTTPException(status_code=404, detail="Unknown user")

    # first verify the nonce
    provided = base64.b64decode(req.nonce)
    stored = db.get_pending_challenge(req.username, "change_password")
    if stored is None or provided != stored:
        logging.warning(f"No valid pending challenge for '{req.username}' (change_password)")
        raise HTTPException(status_code=400, detail="Invalid or expired challenge")

    # now verify the signature over the new encrypted private key
    encrypted_privkey = base64.b64decode(req.encrypted_privkey)
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
            base64.b64decode(req.privkey_nonce)
        )
        logging.info(f"Password changed for '{req.username}'")
        db.delete_challenge(req.username)
        return {"status": "ok", "message": "password changed"}
    except InvalidSignature:
        logging.warning(f"Bad signature for change_password of '{req.username}'")
        db.delete_challenge(req.username)
        raise HTTPException(status_code=401, detail="Bad signature")
