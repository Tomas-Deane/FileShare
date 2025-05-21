#!/usr/bin/env python3
import base64
import secrets
import logging

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from utils import send_response

async def handle_message(msg, session, writer, db):
    action = msg.get('action')
    if action == 'signup':
        await _handle_signup(msg, writer, db)
    elif action == 'login':
        await _handle_login(msg, writer, db, session)
    elif action == 'authenticate':
        await _handle_authenticate(msg, writer, db, session)
    else:
        logging.error(f"Unknown action received: {action}")
        await send_response(writer, {'status':'error', 'error':'Unknown action'})

async def _handle_signup(msg, writer, db): # this checks if user is already in database by name, if so error, else add new user to db
    username = msg['username']
    salt = base64.b64decode(msg['salt'])
    opslimit = msg['argon2_opslimit']
    memlimit = msg['argon2_memlimit']
    public_key = base64.b64decode(msg['public_key'])
    encrypted_privkey = base64.b64decode(msg['encrypted_privkey'])
    privkey_nonce = base64.b64decode(msg['privkey_nonce'])

    logging.debug(
        f"Signup for '{username}': salt={salt.hex()}, ops={opslimit}, "
        f"mem={memlimit}, pub={public_key.hex()}"
    )
    if db.get_user(username):
        await send_response(writer, {'status':'error','error':'User already exists'})
    else:
        db.add_user(username, salt, opslimit, memlimit,
                    public_key, encrypted_privkey, privkey_nonce)
        await send_response(writer, {'status':'ok'})

async def _handle_login(msg, writer, db, session): # if user in db: generate challenge nonce, send to client with saved (encrypted) user data. Save session username/challenge for validation on client response
    username = msg['username']
    logging.debug(f"Login request for '{username}'")
    user = db.get_user(username)
    if not user:
        await send_response(writer, {'status':'error','error':'Unknown user'})
        return

    challenge = secrets.token_bytes(32)
    session['username'] = username
    session['challenge'] = challenge
    logging.debug(f"Challenge for '{username}': {challenge.hex()}")

    await send_response(writer, {
        'status':'challenge',
        'nonce': base64.b64encode(challenge).decode(),
        'salt':  base64.b64encode(user['salt']).decode(),
        'argon2_opslimit': user['argon2_opslimit'],
        'argon2_memlimit': user['argon2_memlimit'],
        'encrypted_privkey': base64.b64encode(user['encrypted_privkey']).decode(),
        'privkey_nonce':     base64.b64encode(user['privkey_nonce']).decode()
    })

async def _handle_authenticate(msg, writer, db, session): # take signature from client and verify
    username = msg['username']
    signature = base64.b64decode(msg['signature'])
    logging.debug(f"Authenticate attempt for '{username}'")

    user = db.get_user(username)
    if (not user or
        session.get('username') != username or
        session.get('challenge') is None):
        logging.warning(f"Invalid session state for '{username}'")
        await send_response(writer, {'status':'error','error':'Invalid session'})
        return

    pubkey = user['public_key']
    challenge = session['challenge']
    logging.debug(f"Verifying signature: challenge={challenge.hex()}")

    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(signature, challenge) # this .verify uses complex discrete logarithm math to verify the challenge was signed by the client's private key using only the clients public key
        logging.info(f"Signature valid for '{username}'")
        session.pop('challenge', None)
        await send_response(writer, {'status':'ok','message':'login successful'})
    except InvalidSignature:
        logging.warning(f"Bad signature for '{username}'")
        await send_response(writer, {'status':'error','error':'Bad signature'})