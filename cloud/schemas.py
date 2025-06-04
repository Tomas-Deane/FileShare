#!/usr/bin/env python3
"""
Common request schemas for FileShare API (shared between server and handlers).
"""
from pydantic import BaseModel, conint
from typing import Optional

# Constants for Argon2 parameter limits
MIN_OPS_LIMIT = 1
MAX_OPS_LIMIT = 4294967295  # Maximum value for uint32_t
MIN_MEM_LIMIT = 8192  # 8KB minimum memory limit
MAX_MEM_LIMIT = 4294967295  # Maximum value for uint32_t (in bytes)


class SignupRequest(BaseModel):
    username: str
    salt: str
    argon2_opslimit: conint(gt=0, lt=MAX_OPS_LIMIT)  # Must be between 1 and MAX_OPS_LIMIT
    argon2_memlimit: conint(gt=MIN_MEM_LIMIT, lt=MAX_MEM_LIMIT)  # Must be between 8KB and MAX_MEM_LIMIT
    public_key: str
    encrypted_privkey: str
    privkey_nonce: str
    encrypted_kek: str
    kek_nonce: str
    identity_key: str  # X3DH IK_pub (base64)
    signed_pre_key: str  # X3DH SPK_pub (base64)
    signed_pre_key_sig: str  # X3DH SPK_signature (base64)
    one_time_pre_keys: list[str]  # X3DH OPKs_pub (base64 list)

    # ← NEW: initial TOFU/key backup, encrypted under sessionKek
    encrypted_backup: str
    backup_nonce: str


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
    argon2_opslimit: conint(gt=0, lt=MAX_OPS_LIMIT)  # Must be between 1 and MAX_OPS_LIMIT
    argon2_memlimit: conint(gt=MIN_MEM_LIMIT, lt=MAX_MEM_LIMIT)  # Must be between 8KB and MAX_MEM_LIMIT
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
    file_id: int
    nonce: str
    signature: str


class DeleteFileRequest(BaseModel):
    username: str
    file_id: int
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
    username: str  # The requesting user (for signature verification)
    target_username: str  # The user we want OPK for
    nonce: str
    signature: str


class OPKResponse(BaseModel):
    opk_id: int
    pre_key: str


class ShareFileRequest(BaseModel):
    username: str
    file_id: int
    recipient_username: str
    signature: str
    EK_pub: str
    IK_pub: str
    SPK_pub: str
    SPK_signature: str
    OPK_ID: Optional[int] = None
    encrypted_file_key: str
    file_key_nonce: str  
    nonce: str

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

class RetrieveFileDEKRequest(BaseModel):
    username: str
    file_id: int
    nonce: str
    signature: str

class RetrieveFileDEKResponse(BaseModel):
    status: str
    encrypted_dek: str
    dek_nonce: str

class DownloadSharedFileRequest(BaseModel):
    username: str
    share_id: int
    nonce: str
    signature: str

class ListMatchingUsersRequest(BaseModel):
    username: str  # The user making the request
    nonce: str     # Challenge nonce
    signature: str # Signature of the nonce
    search_query: str  # The search query from the user

# list every user who has ever shared at least one file with the challenge initiator
class ListSharersRequest(BaseModel):
    username: str
    nonce: str
    signature: str

class ClearUserOPKsRequest(BaseModel):
    username: str  # The user making the request
    target_username: str  # The user whose OPKs we want to clear
    nonce: str
    signature: str

class PreviewSharedFileRequest(BaseModel):
    username: str
    share_id: int
    nonce: str
    signature: str

class GetOPKCountRequest(BaseModel):
    username: str
    target_username: str
    nonce: str
    signature: str

class GetOPKCountResponse(BaseModel):
    status: str
    count: int


class ListFileSharesRequest(BaseModel):
    username: str  # Owner
    file_id: int
    nonce: str
    signature: str


class ListFileSharesResponse(BaseModel):
    status: str
    shares: list[UserData]


class RotateFileRequest(BaseModel):
    username: str
    file_id: int
    encrypted_file: str
    file_nonce: str
    encrypted_dek: str
    dek_nonce: str
    nonce: str
    signature: str

class RotateFileResponse(BaseModel):
    status: str
    message: str
