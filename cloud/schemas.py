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
    identity_key: str  # X3DH IK_pub (base64)
    signed_pre_key: str  # X3DH SPK_pub (base64)
    signed_pre_key_sig: str  # X3DH SPK_signature (base64)
    one_time_pre_keys: list[str]  # X3DH OPKs_pub (base64 list)


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


class GetPreKeyBundleRequest(BaseModel):
    username: str
    nonce: str
    signature: str

class AddPreKeyBundleRequest(BaseModel):
    username: str
    nonce: str
    signature: str
    IK_pub: str
    SPK_pub: str
    SPK_signature: str

class PreKeyBundleResponse(BaseModel):
    IK_pub: str
    SPK_pub: str
    SPK_signature: str

class AddPreKeyBundleResponse(BaseModel):
    status: str
    message: str


class AddOPKsRequest(BaseModel):
    username: str
    pre_keys: list[str]  # List of base64 encoded pre-keys
    nonce: str
    signature: str


class GetOPKRequest(BaseModel):
    username: str
    nonce: str
    signature: str


class OPKResponse(BaseModel):
    opk_id: int
    pre_key: str


class ShareFileRequest(BaseModel):
    username: str
    filename: str
    recipient_username: str
    encrypted_key: str
    EK_pub: str
    IK_pub: str
    nonce: str
    signature: str


class ListSharedFilesRequest(BaseModel):
    username: str
    nonce: str
    signature: str


class SharedFileResponse(BaseModel):
    share_id: int
    file_id: int
    filename: str
    EK_pub: str
    IK_pub: str
    shared_at: str


class RemoveSharedFileRequest(BaseModel):
    username: str
    share_id: int
    nonce: str
    signature: str
    
class AddOPKsRequest(BaseModel):    
    username: str
    pre_keys: list[str]
    nonce: str
    signature: str


class BackupTOFURequest(BaseModel):
    username: str 

class BackupTOFUResponse(BaseModel):
    status: str
    encrypted_backup: str


class GetBackupTOFURequest(BaseModel):
    username: str
    nonce: str
    signature: str


class GetBackupTOFUResponse(BaseModel):
    status: str
    encrypted_backup: str
    backup_nonce: str


class ListUsersRequest(BaseModel):
    username: str
    nonce: str
    signature: str

class UserData(BaseModel):
    id: int
    username: str

class ListUsersResponse(BaseModel):
    status: str
    users: list[UserData]
