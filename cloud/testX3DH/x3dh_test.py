"""
X3DH (Extended Triple Diffie-Hellman) Implementation Reference
============================================================

This script demonstrates the X3DH protocol, which is used for secure key exchange
in end-to-end encrypted messaging systems. It's based on the Signal Protocol.

Key Concepts:
------------
1. Identity Key (IK): Long-term Ed25519 key pair for signing
2. Signed Prekey (SPK): Medium-term Curve25519 key pair, signed by IK
3. One-time Prekey (OPK): Short-term Curve25519 key pairs, used once
4. Ephemeral Key (EK): Temporary Curve25519 key pair for each exchange

The protocol provides:
- Perfect Forward Secrecy (PFS)
- Deniability
- Protection against replay attacks
- Protection against key compromise
"""

import nacl.public
import nacl.signing
import nacl.hash
import nacl.encoding
import nacl.secret
import nacl.utils
import nacl.bindings
from typing import Dict, List
import time

class User:
    """
    Represents a user in the X3DH system.
    Each user has:
    - An Identity Key (IK) for signing
    - A Signed Prekey (SPK) for encryption
    - A pool of One-time Prekeys (OPKs)
    - A record of shared files
    - A record of verified public keys (TOFU)
    """
    def __init__(self, user_id: str):
        print(f"\n=== Creating New User: {user_id} ===")
        self.user_id = user_id
        
        # Generate Identity Key (IK) - Ed25519 for signing
        # This is the user's long-term identity
        self.identity_key = nacl.signing.SigningKey.generate()
        self.identity_key_verify = self.identity_key.verify_key
        print(f"✓ Generated Identity Key (IK)")
        print(f"  - Type: Ed25519 (for signing)")
        print(f"  - Public Key: {self.identity_key_verify.encode().hex()[:16]}...")
        
        # Initialize other keys
        self.signed_prekey = None
        self.signed_prekey_signature = None
        self.one_time_prekeys = []
        self.shared_files = {}  # file_id -> {recipient_id: encrypted_key}
        
        # TOFU: Store verified public keys
        self.verified_keys = {}  # user_id -> {ik, spk, last_verified}

    def generate_prekeys(self, opk_count: int = 100):
        """
        Generate the user's prekeys:
        1. A Signed Prekey (SPK) - signed by the Identity Key
        2. A batch of One-time Prekeys (OPKs)
        
        Args:
            opk_count: Number of one-time prekeys to generate (default: 100)
        """
        print(f"\n=== Generating Prekeys for {self.user_id} ===")
        
        # Generate Signed Prekey (SPK) - Curve25519 for encryption
        self.signed_prekey = nacl.public.PrivateKey.generate()
        print(f"✓ Generated Signed Prekey (SPK)")
        print(f"  - Type: Curve25519 (for encryption)")
        print(f"  - Public Key: {self.signed_prekey.public_key.encode().hex()[:16]}...")
        
        # Sign the SPK with the Identity Key to prove ownership
        self.signed_prekey_signature = self.identity_key.sign(
            self.signed_prekey.public_key.encode()
        ).signature
        print(f"✓ Signed SPK with Identity Key")
        print(f"  - Signature: {self.signed_prekey_signature.hex()[:16]}...")

        # Generate One-time Prekeys (OPKs) - Curve25519 for encryption
        self.one_time_prekeys = [
            nacl.public.PrivateKey.generate() for _ in range(opk_count)
        ]
        print(f"✓ Generated {opk_count} One-time Prekeys (OPKs)")
        print(f"  - Type: Curve25519 (for encryption)")
        print(f"  - Each OPK will be used only once")
        print(f"  - First OPK Public Key: {self.one_time_prekeys[0].public_key.encode().hex()[:16]}...")

    def rotate_signed_prekey(self):
        """
        Rotate the Signed Prekey (SPK).
        This should be done periodically (e.g., weekly) to maintain security.
        """
        print(f"\n=== Rotating Signed Prekey for {self.user_id} ===")
        old_spk = self.signed_prekey
        
        # Generate new SPK
        self.signed_prekey = nacl.public.PrivateKey.generate()
        print(f"✓ Generated new Signed Prekey")
        print(f"  - Old SPK: {old_spk.public_key.encode().hex()[:16]}...")
        print(f"  - New SPK: {self.signed_prekey.public_key.encode().hex()[:16]}...")
        
        # Sign new SPK with Identity Key
        self.signed_prekey_signature = self.identity_key.sign(
            self.signed_prekey.public_key.encode()
        ).signature
        print(f"✓ Signed new SPK with Identity Key")

    def check_and_refill_opks(self, threshold: int = 20):
        """
        Check if we're running low on One-time Prekeys and refill if necessary.
        
        Args:
            threshold: Minimum number of OPKs to maintain (default: 20)
        """
        if len(self.one_time_prekeys) < threshold:
            print(f"\n=== Refilling One-time Prekeys for {self.user_id} ===")
            print(f"  - Current OPK count: {len(self.one_time_prekeys)}")
            print(f"  - Threshold: {threshold}")
            
            # Generate new batch of OPKs
            new_opks = [nacl.public.PrivateKey.generate() for _ in range(100)]
            self.one_time_prekeys.extend(new_opks)
            print(f"✓ Generated and added {len(new_opks)} new OPKs")
            print(f"  - New total: {len(self.one_time_prekeys)}")
            print(f"  - First new OPK: {new_opks[0].public_key.encode().hex()[:16]}...")

    def verify_key_fingerprint(self, user_id: str, ik_public: bytes, spk_public: bytes, 
                             verification_code: str = None) -> bool:
        """
        Verify another user's public keys using TOFU/OOB verification.
        
        Args:
            user_id: ID of the user whose keys to verify
            ik_public: Identity Key public key to verify
            spk_public: Signed Prekey public key to verify
            verification_code: Optional verification code for OOB verification
            
        Returns:
            bool: True if keys are verified, False otherwise
        """
        print(f"\n=== Verifying Keys for {user_id} ===")
        
        # Generate fingerprint from public keys
        fingerprint = nacl.hash.blake2b(
            ik_public + spk_public,
            encoder=nacl.encoding.HexEncoder
        ).decode()[:16]
        
        if verification_code:
            # OOB verification
            if verification_code == fingerprint:
                print(f"  ✓ OOB verification successful")
                print(f"  - Verification code matches fingerprint")
                self.verified_keys[user_id] = {
                    'ik': ik_public,
                    'spk': spk_public,
                    'last_verified': time.time()
                }
                return True
            else:
                print(f"  ✗ OOB verification failed")
                print(f"  - Verification code doesn't match fingerprint")
                return False
        else:
            # TOFU verification
            if user_id in self.verified_keys:
                stored_ik = self.verified_keys[user_id]['ik']
                stored_spk = self.verified_keys[user_id]['spk']
                
                if stored_ik == ik_public and stored_spk == spk_public:
                    print(f"  ✓ TOFU verification successful")
                    print(f"  - Keys match previously verified keys")
                    self.verified_keys[user_id]['last_verified'] = time.time()
                    return True
                else:
                    print(f"  ✗ TOFU verification failed")
                    print(f"  - Keys don't match previously verified keys")
                    return False
            else:
                print(f"  ! First-time key verification")
                print(f"  - Fingerprint: {fingerprint}")
                print(f"  - Please verify this fingerprint out-of-band")
                print(f"  - Store these keys as verified? (y/n)")
                
                # In a real system, this would be handled by the UI
                # For simulation, we'll assume the user verifies
                self.verified_keys[user_id] = {
                    'ik': ik_public,
                    'spk': spk_public,
                    'last_verified': time.time()
                }
                return True

    def get_key_fingerprint(self) -> str:
        """
        Get the fingerprint of this user's public keys for OOB verification.
        
        Returns:
            str: 16-character hex fingerprint of the public keys
        """
        fingerprint = nacl.hash.blake2b(
            self.identity_key_verify.encode() + self.signed_prekey.public_key.encode(),
            encoder=nacl.encoding.HexEncoder
        ).decode()[:16]
        return fingerprint

class Server:
    """
    Simulates a server that manages users and files.
    In a real system, this would be a distributed service.
    """
    def __init__(self):
        self.users: Dict[str, User] = {}
        self.files: Dict[str, bytes] = {}
        print("\n=== Initializing Server ===")

    def register_user(self, user: User):
        """Register a new user with the server."""
        self.users[user.user_id] = user
        print(f"\n=== Registered User {user.user_id} ===")
        print(f"  - Identity Key: {user.identity_key_verify.encode().hex()[:16]}...")
        print(f"  - Signed Prekey: {user.signed_prekey.public_key.encode().hex()[:16]}...")
        print(f"  - One-time Prekeys: {len(user.one_time_prekeys)} available")

    def get_user_keys(self, user_id: str) -> dict:
        """
        Get a user's public keys for X3DH.
        Returns:
            Dictionary containing:
            - Identity Key (IK)
            - Signed Prekey (SPK)
            - SPK Signature
            - One One-time Prekey (OPK)
            - OPK Index (to track which OPK was used)
        """
        user = self.users[user_id]
        print(f"\n=== Fetching Keys for User {user_id} ===")
        
        # Get one OPK from the pool
        opk = user.one_time_prekeys[0]  # Don't remove it yet
        print(f"  - Retrieved one OPK from pool")
        print(f"  - Remaining OPKs: {len(user.one_time_prekeys)}")
        
        return {
            'identity_key': user.identity_key_verify.encode(),
            'signed_prekey': user.signed_prekey.public_key.encode(),
            'signed_prekey_signature': user.signed_prekey_signature,
            'one_time_prekey': opk.public_key.encode(),
            'opk_index': 0  # Track which OPK we're using
        }

    def store_file(self, file_id: str, encrypted_data: bytes):
        """Store an encrypted file on the server."""
        self.files[file_id] = encrypted_data
        print(f"\n=== Stored File {file_id} ===")
        print(f"  - Size: {len(encrypted_data)} bytes")
        print(f"  - Encrypted: Yes")

    def get_file(self, file_id: str) -> bytes:
        """Retrieve an encrypted file from the server."""
        print(f"\n=== Retrieved File {file_id} ===")
        return self.files[file_id]

def simulate_x3dh_interactions():
    """
    Simulate a complete X3DH interaction between two users.
    This demonstrates:
    1. User registration
    2. Key verification (TOFU/OOB)
    3. File sharing
    4. File decryption
    5. Key rotation
    6. Access revocation
    """
    print("\n=== Starting X3DH Interaction Simulation ===\n")
    server = Server()

    # === User Signup ===
    print("\n=== User Signup Process ===")
    print("-------------------------")
    print("Step 1: Create and register users")
    print("-------------------------------")
    
    # Create and register Alice
    alice = User("alice")
    alice.generate_prekeys()
    server.register_user(alice)

    # Create and register Bob
    bob = User("bob")
    bob.generate_prekeys()
    server.register_user(bob)

    # === Key Verification ===
    print("\n=== Key Verification Process ===")
    print("----------------------------")
    print("Step 2: Verify public keys")
    print("------------------------")
    
    # Get Bob's public keys
    bob_keys = server.get_user_keys("bob")
    
    # Alice verifies Bob's keys
    print("\nAlice verifying Bob's keys:")
    alice_verifies_bob = alice.verify_key_fingerprint(
        "bob",
        bob_keys['identity_key'],
        bob_keys['signed_prekey']
    )
    
    # Bob verifies Alice's keys
    print("\nBob verifying Alice's keys:")
    bob_verifies_alice = bob.verify_key_fingerprint(
        "alice",
        alice.identity_key_verify.encode(),
        alice.signed_prekey.public_key.encode()
    )
    
    if not (alice_verifies_bob and bob_verifies_alice):
        print("\n! Key verification failed. Aborting file sharing.")
        return

    # === File Sharing ===
    print("\n=== File Sharing Process ===")
    print("-------------------------")
    print("Step 3: Alice shares a file with Bob")
    print("--------------------------------")
    
    # Create a test file
    file_id = "file1"
    file_data = b"This is a secret file"
    print(f"  - File ID: {file_id}")
    print(f"  - Content: {file_data.decode()}")
    
    # Get Bob's keys for X3DH
    print("\nStep 4: Alice gets Bob's keys")
    print("---------------------------")
    bob_keys = server.get_user_keys("bob")
    
    # Verify Bob's keys before proceeding
    if not alice.verify_key_fingerprint("bob", bob_keys['identity_key'], bob_keys['signed_prekey']):
        print("! Key verification failed. Aborting file sharing.")
        return

    # Alice performs X3DH
    print("\nStep 5: Alice performs X3DH")
    print("-------------------------")
    alice_ek = nacl.public.PrivateKey.generate()
    print(f"  - Generated Ephemeral Key (EK)")
    
    # Convert Bob's IK to Curve25519
    bob_ik_curve = nacl.public.PublicKey(
        nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(bob_keys['identity_key'])
    )
    print(f"  - Converted Bob's IK to Curve25519")
    
    # Perform the three DH operations
    print("\nPerforming Diffie-Hellman operations:")
    dh1 = nacl.bindings.crypto_scalarmult(alice_ek.encode(), bob_ik_curve.encode())
    print(f"  - DH1: EK × IK = {dh1.hex()[:16]}...")
    
    dh2 = nacl.bindings.crypto_scalarmult(alice_ek.encode(), bob_keys['signed_prekey'])
    print(f"  - DH2: EK × SPK = {dh2.hex()[:16]}...")
    
    dh3 = nacl.bindings.crypto_scalarmult(alice_ek.encode(), bob_keys['one_time_prekey'])
    print(f"  - DH3: EK × OPK = {dh3.hex()[:16]}...")
    
    # Combine the shared secrets
    shared_secret = nacl.hash.blake2b(dh1 + dh2 + dh3, encoder=nacl.encoding.RawEncoder)[:32]
    print(f"\n  - Combined secrets using BLAKE2b")
    print(f"  - Final shared secret: {shared_secret.hex()[:16]}...")
    
    # Encrypt the file
    print("\nStep 6: Encrypting file")
    print("---------------------")
    secret_box = nacl.secret.SecretBox(shared_secret)
    nonce = nacl.utils.random(secret_box.NONCE_SIZE)
    encrypted_file = secret_box.encrypt(file_data, nonce)
    print(f"  - File encrypted successfully")
    print(f"  - Nonce: {nonce.hex()[:16]}...")
    print(f"  - Encrypted data length: {len(encrypted_file)} bytes")
    
    # Store the encrypted file and sharing info
    server.store_file(file_id, encrypted_file)
    alice.shared_files[file_id] = {
        'bob': {
            'encrypted_key': encrypted_file,
            'ephemeral_key': alice_ek.public_key.encode(),
            'nonce': nonce,  # Store the nonce
            'used_opk_index': bob_keys['opk_index']  # Store the OPK index instead of the key
        }
    }
    print(f"  - File stored and sharing info recorded")

    # === Bob Decrypts File ===
    print("\n=== File Decryption Process ===")
    print("----------------------------")
    print("Step 7: Bob retrieves and decrypts the file")
    print("----------------------------------------")
    
    # Bob gets the encrypted file and nonce
    encrypted_file = server.get_file(file_id)
    nonce = alice.shared_files[file_id]['bob']['nonce']
    used_opk_index = alice.shared_files[file_id]['bob']['used_opk_index']
    print(f"  - Retrieved nonce: {nonce.hex()[:16]}...")
    print(f"  - Encrypted data length: {len(encrypted_file)} bytes")
    
    # Bob performs X3DH
    print("\nStep 8: Bob performs X3DH")
    print("------------------------")
    print("Performing Diffie-Hellman operations:")
    
    dh1 = nacl.bindings.crypto_scalarmult(bob.identity_key.to_curve25519_private_key().encode(), 
                                        alice.shared_files[file_id]['bob']['ephemeral_key'])
    print(f"  - DH1: IK × EK = {dh1.hex()[:16]}...")
    
    dh2 = nacl.bindings.crypto_scalarmult(bob.signed_prekey.encode(), 
                                        alice.shared_files[file_id]['bob']['ephemeral_key'])
    print(f"  - DH2: SPK × EK = {dh2.hex()[:16]}...")
    
    # Get the correct OPK using the stored index
    matching_opk = bob.one_time_prekeys[used_opk_index]
    dh3 = nacl.bindings.crypto_scalarmult(matching_opk.encode(), 
                                        alice.shared_files[file_id]['bob']['ephemeral_key'])
    print(f"  - DH3: OPK × EK = {dh3.hex()[:16]}...")
    
    # Remove the used OPK
    bob.one_time_prekeys.pop(used_opk_index)
    print(f"  - Removed used OPK from pool")
    
    # Combine the shared secrets
    bob_shared_secret = nacl.hash.blake2b(dh1 + dh2 + dh3, encoder=nacl.encoding.RawEncoder)[:32]
    print(f"\n  - Combined secrets using BLAKE2b")
    print(f"  - Final shared secret: {bob_shared_secret.hex()[:16]}...")
    
    # Decrypt the file
    print("\nStep 9: Decrypting file")
    print("---------------------")
    bob_secret_box = nacl.secret.SecretBox(bob_shared_secret)
    try:
        decrypted_file = bob_secret_box.decrypt(encrypted_file)
        print(f"  - File decrypted successfully")
        print(f"  - Content: {decrypted_file.decode()}")
    except nacl.exceptions.CryptoError as e:
        print(f"  - Decryption failed: {str(e)}")
        print(f"  - Shared secret comparison:")
        print(f"    Alice: {shared_secret.hex()[:16]}...")
        print(f"    Bob:   {bob_shared_secret.hex()[:16]}...")
        raise

    # === Key Rotation ===
    print("\n=== Key Rotation Process ===")
    print("-------------------------")
    print("Step 10: Rotating Bob's signed prekey")
    print("--------------------------------")
    bob.rotate_signed_prekey()
    
    print("\nStep 11: Checking and refilling OPKs")
    print("---------------------------------")
    bob.check_and_refill_opks()

    # === Access Revocation ===
    print("\n=== Access Revocation Process ===")
    print("-----------------------------")
    print("Step 12: Alice revokes Bob's access")
    print("-----------------------------")
    
    if file_id in alice.shared_files and 'bob' in alice.shared_files[file_id]:
        print("  - Starting secure revocation process")
        
        # 1. First, decrypt the file using Alice's original key
        print("\nStep 12.1: Decrypting file with original key")
        print("----------------------------------------")
        original_shared_secret = shared_secret  # We still have this from earlier
        original_secret_box = nacl.secret.SecretBox(original_shared_secret)
        decrypted_file = original_secret_box.decrypt(encrypted_file)
        print(f"  - File decrypted successfully")
        
        # 2. Generate new ephemeral key and perform X3DH with remaining users
        print("\nStep 12.2: Re-encrypting file with new key")
        print("----------------------------------------")
        new_ek = nacl.public.PrivateKey.generate()
        print(f"  - Generated new Ephemeral Key (EK)")
        
        # Store new sharing info
        new_sharing_info = {}
        new_encrypted_file = None  # Will store the last encrypted version
        
        # Re-encrypt for each remaining user (including Alice)
        remaining_users = [user_id for user_id in alice.shared_files[file_id].keys() if user_id != 'bob']
        if not remaining_users:
            # If no other users, re-encrypt for Alice
            remaining_users = ['alice']
        
        for user_id in remaining_users:
            print(f"  - Re-encrypting for user: {user_id}")
            
            # Get user's keys
            user_keys = server.get_user_keys(user_id)
            
            # Convert user's IK to Curve25519
            user_ik_curve = nacl.public.PublicKey(
                nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(user_keys['identity_key'])
            )
            
            # Perform X3DH
            dh1 = nacl.bindings.crypto_scalarmult(new_ek.encode(), user_ik_curve.encode())
            dh2 = nacl.bindings.crypto_scalarmult(new_ek.encode(), user_keys['signed_prekey'])
            dh3 = nacl.bindings.crypto_scalarmult(new_ek.encode(), user_keys['one_time_prekey'])
            
            # Generate new shared secret
            new_shared_secret = nacl.hash.blake2b(dh1 + dh2 + dh3, encoder=nacl.encoding.RawEncoder)[:32]
            
            # Encrypt the file
            new_secret_box = nacl.secret.SecretBox(new_shared_secret)
            new_encrypted_file = new_secret_box.encrypt(decrypted_file)
            
            # Store new sharing info
            new_sharing_info[user_id] = {
                'encrypted_key': new_encrypted_file,
                'ephemeral_key': new_ek.public_key.encode(),
                'used_opk_index': user_keys['opk_index']
            }
        
        # 3. Update server with new encrypted file
        print("\nStep 12.3: Updating server with new encrypted file")
        print("----------------------------------------------")
        if new_encrypted_file is None:
            raise ValueError("No users to re-encrypt for")
            
        server.store_file(file_id, new_encrypted_file)
        print(f"  - New encrypted file stored on server")
        
        # 4. Update Alice's sharing info
        print("\nStep 12.4: Updating sharing information")
        print("------------------------------------")
        alice.shared_files[file_id] = new_sharing_info
        print(f"  - Bob's access has been revoked")
        print(f"  - File has been re-encrypted with new keys")
        print(f"  - Bob can no longer decrypt the file")
    else:
        print(f"  - Bob doesn't have access to file {file_id}")

if __name__ == "__main__":
    simulate_x3dh_interactions()
