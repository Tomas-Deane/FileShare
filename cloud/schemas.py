#!/usr/bin/env python3
"""
Common request schemas for FileShare API (shared between server and handlers).
"""
from pydantic import BaseModel


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