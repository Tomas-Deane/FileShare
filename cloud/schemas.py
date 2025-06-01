#!/usr/bin/env python3
"""
Common request schemas for FileShare API (shared between server and handlers).
"""
from pydantic import BaseModel, Field, validator
import re
import base64

# Maximum file size (100MB)
MAX_FILE_SIZE = 100 * 1024 * 1024

# Allowed file extensions and their MIME types
ALLOWED_EXTENSIONS = {
    'txt': 'text/plain',
    'pdf': 'application/pdf',
    'png': 'image/png',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'gif': 'image/gif',
    'doc': 'application/msword',
    'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'xls': 'application/vnd.ms-excel',
    'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'zip': 'application/zip',
    'rar': 'application/x-rar-compressed',
    '7z': 'application/x-7z-compressed'
}

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

    @validator('filename')
    def validate_filename(cls, v):
        # Check file extension
        ext = v.split('.')[-1].lower() if '.' in v else ''
        if ext not in ALLOWED_EXTENSIONS:
            raise ValueError(f"File type not allowed. Allowed types: {', '.join(ALLOWED_EXTENSIONS.keys())}")
        return v

    @validator('encrypted_file')
    def validate_file_size(cls, v):
        # Decode base64 and check size
        try:
            file_data = base64.b64decode(v)
            if len(file_data) > MAX_FILE_SIZE:
                raise ValueError(f"File too large. Maximum size is {MAX_FILE_SIZE/1024/1024}MB")
        except Exception as e:
            raise ValueError(f"Invalid base64 encoding: {str(e)}")
        return v


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
    username: str  # The requesting user's username (for challenge verification)
    target_username: str  # The username whose prekey bundle we want to get
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
    opks: list[str]  # List of base64 encoded pre-keys
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
    encrypted_file_key: str
    EK_pub: str
    IK_pub: str
    nonce: str
    signature: str


class ListSharedFilesRequest(BaseModel):
    """List *all* files shared to me (no filter)."""
    username: str
    nonce: str
    signature: str

# New: list files I shared TO a particular user
class ListSharedToRequest(BaseModel):
    username: str
    target_username: str
    nonce: str
    signature: str

# New: list files shared FROM a particular user to me
class ListSharedFromRequest(BaseModel):
    username: str
    target_username: str
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


class BackupTOFURequest(BaseModel):
    username: str
    encrypted_backup: str
    backup_nonce: str
    nonce: str
    signature: str

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
