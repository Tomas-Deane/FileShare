#!/usr/bin/env python3
import os
import pymysql as connector
import logging
import datetime
import threading
from dbutils.pooled_db import PooledDB
from typing import List, Tuple, Optional

# Database connection parameters (will use env variables)
DB_USER     = os.environ.get('DB_USER',     'nrmc')
DB_PASSWORD = os.environ.get('DB_PASSWORD', 'nrmc')
DB_HOST     = os.environ.get('DB_HOST',     '127.0.0.1')
DB_PORT     = int(os.environ.get('DB_PORT', '3306'))
DB_NAME     = os.environ.get('DB_NAME',     'nrmc')

def init_db():
    """
    Ensure the users, username_map, pending_challenges, and files tables
    all exist. Any that are already there will be left intact.
    """
    conn = connector.connect(
        user     = DB_USER,
        password = DB_PASSWORD,
        host     = DB_HOST,
        port     = DB_PORT,
        database = DB_NAME,
        charset='utf8mb4'
    )
    cursor = conn.cursor()

    # 1) users
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id                  BIGINT AUTO_INCREMENT PRIMARY KEY,
        salt                BLOB                NOT NULL,
        argon2_opslimit     INT                 NOT NULL,
        argon2_memlimit     INT                 NOT NULL,
        public_key          BLOB                NOT NULL,
        encrypted_privkey   BLOB                NOT NULL,
        privkey_nonce       BLOB                NOT NULL,
        encrypted_kek       BLOB                NOT NULL,
        kek_nonce           BLOB                NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)

    # 2) username_map
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS username_map (
        username            VARCHAR(255)        PRIMARY KEY,
        user_id             BIGINT              NOT NULL,
        CONSTRAINT fk_um_user
          FOREIGN KEY (user_id)
          REFERENCES users(id)
          ON DELETE CASCADE
          ON UPDATE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)

    # 3) pending_challenges
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS pending_challenges (
        user_id             BIGINT              NOT NULL,
        operation           VARCHAR(64)         NOT NULL,
        challenge           VARBINARY(32)       NOT NULL,
        created_at          DATETIME            NOT NULL,
        PRIMARY KEY (user_id, operation),
        CONSTRAINT fk_pc_user
          FOREIGN KEY (user_id)
          REFERENCES users(id)
          ON DELETE CASCADE
          ON UPDATE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)

    # 4) files
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS files (
        id                  BIGINT AUTO_INCREMENT PRIMARY KEY,
        owner_id            BIGINT              NOT NULL,
        filename            VARCHAR(255)        NOT NULL,
        encrypted_file      LONGBLOB            NOT NULL,
        file_nonce          BLOB                NOT NULL,
        encrypted_dek       BLOB                NOT NULL,
        dek_nonce           BLOB                NOT NULL,
        created_at          DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_file_owner
          FOREIGN KEY (owner_id)
          REFERENCES users(id)
          ON DELETE CASCADE
          ON UPDATE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)

    # 5) pre_key_bundle
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS pre_key_bundle (
        id                  BIGINT AUTO_INCREMENT PRIMARY KEY,
        user_id             BIGINT              NOT NULL,
        IK_pub              BLOB                NOT NULL,
        SPK_pub             BLOB                NOT NULL,
        SPK_signature       BLOB                NOT NULL,
        created_at          DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_pre_key_user
          FOREIGN KEY (user_id)
          REFERENCES users(id)
          ON DELETE CASCADE
          ON UPDATE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)

    # 6) opks (One-Time Pre-Keys)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS opks (
        id                  BIGINT AUTO_INCREMENT PRIMARY KEY,
        user_id             BIGINT              NOT NULL,
        opk_id              BIGINT              NOT NULL CHECK (opk_id >= 0),
        pre_key             BLOB                NOT NULL,
        consumed            BOOLEAN             NOT NULL DEFAULT FALSE,
        created_at          DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_opks_user
          FOREIGN KEY (user_id)
          REFERENCES users(id)
          ON DELETE CASCADE
          ON UPDATE CASCADE,
        INDEX idx_user_consumed (user_id, consumed),
        UNIQUE KEY unique_opk_id (user_id, opk_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)

    # 7) shared_files
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS shared_files (
        share_id             BIGINT AUTO_INCREMENT PRIMARY KEY,
        file_id              BIGINT              NOT NULL,
        recipient_id         BIGINT              NOT NULL,
        EK_pub               BLOB                NOT NULL,
        IK_pub               BLOB                NOT NULL,
        SPK_pub              BLOB                NOT NULL,
        SPK_signature        BLOB                NOT NULL,
        encrypted_file_key   BLOB                NOT NULL,
        file_key_nonce       BLOB                NOT NULL,
        OPK_id               BIGINT              NULL,
        shared_at            DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_shared_file
          FOREIGN KEY (file_id)
          REFERENCES files(id)
          ON DELETE CASCADE
          ON UPDATE CASCADE,
        CONSTRAINT fk_shared_recipient
          FOREIGN KEY (recipient_id)
          REFERENCES users(id)
          ON DELETE CASCADE
          ON UPDATE CASCADE,
        INDEX idx_file_recipient (file_id, recipient_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)

    # 8) tofu_backups
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS tofu_backups (
        id                  BIGINT AUTO_INCREMENT PRIMARY KEY,
        user_id             BIGINT              NOT NULL,
        encrypted_data      LONGBLOB            NOT NULL,
        backup_nonce        BLOB                NOT NULL,
        created_at          DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_verified       DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_tofu_user
          FOREIGN KEY (user_id)
          REFERENCES users(id)
          ON DELETE CASCADE
          ON UPDATE CASCADE,
        INDEX idx_user (user_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)

    conn.commit()
    cursor.close()
    conn.close()


class UserDB:
    """
    Thread-safe database wrapper with connection pooling.
    Each thread gets its own connection from the pool.
    """
    _pool = None
    _local = threading.local()

    def __init__(self):
        if UserDB._pool is None:
            UserDB._pool = PooledDB(
                creator=connector,
                maxconnections=50,
                mincached=5,
                maxcached=10,
                blocking=True,
                maxusage=100,
                setsession=[],
                ping=1,
                user=DB_USER,
                password=DB_PASSWORD,
                host=DB_HOST,
                port=DB_PORT,
                database=DB_NAME,
                charset='utf8mb4',
                cursorclass=connector.cursors.DictCursor
            )

    def _get_connection(self):
        """
        Return (conn, cursor) for the current thread, creating them if necessary.
        """
        try:
            if not hasattr(self._local, 'conn'):
                self._local.conn = UserDB._pool.connection()
                self._local.cursor = self._local.conn.cursor()
            return self._local.conn, self._local.cursor
        except Exception as e:
            logging.error(f"Error getting database connection: {str(e)}")
            raise

    def ensure_connection(self):
        """
        Ping the current connection; if it fails, close it and re‐open.
        """
        try:
            conn, cursor = self._get_connection()
            conn.ping(reconnect=True)
        except Exception as e:
            logging.error(f"Connection error, attempting to reconnect: {str(e)}")
            if hasattr(self._local, 'conn'):
                try:
                    self._local.conn.close()
                except:
                    pass
            if hasattr(self._local, 'cursor'):
                try:
                    self._local.cursor.close()
                except:
                    pass
            delattr(self._local, 'conn')
            delattr(self._local, 'cursor')
            self._get_connection()

    def _get_user_id(self, username: str):
        self.ensure_connection()
        conn, cursor = self._get_connection()
        sql = "SELECT user_id FROM username_map WHERE username = %s"
        cursor.execute(sql, (username,))
        row = cursor.fetchone()
        if not row:
            return None
        return row['user_id']

    def add_user(self, username, salt, opslimit, memlimit,
                 public_key, encrypted_privkey, privkey_nonce,
                 encrypted_kek, kek_nonce):
        conn, cursor = self._get_connection()
        sql_user = """
            INSERT INTO users
                (salt, argon2_opslimit, argon2_memlimit,
                 public_key, encrypted_privkey, privkey_nonce,
                 encrypted_kek, kek_nonce)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(sql_user, (
            salt,
            opslimit,
            memlimit,
            public_key,
            encrypted_privkey,
            privkey_nonce,
            encrypted_kek,
            kek_nonce
        ))
        user_id = cursor.lastrowid

        sql_map = "INSERT INTO username_map (username, user_id) VALUES (%s, %s)"
        cursor.execute(sql_map, (username, user_id))
        conn.commit()
        return user_id

    def get_user(self, username: str):
        self.ensure_connection()
        conn, cursor = self._get_connection()
        sql = """
            SELECT
              u.id                   AS user_id,
              u.salt                 AS salt,
              u.argon2_opslimit      AS argon2_opslimit,
              u.argon2_memlimit      AS argon2_memlimit,
              u.public_key           AS public_key,
              u.encrypted_privkey    AS encrypted_privkey,
              u.privkey_nonce        AS privkey_nonce,
              u.encrypted_kek        AS encrypted_kek,
              u.kek_nonce            AS kek_nonce
            FROM users u
            JOIN username_map m
              ON u.id = m.user_id
            WHERE m.username = %s
            LIMIT 1
        """
        cursor.execute(sql, (username,))
        row = cursor.fetchone()
        if not row:
            return None
        return row  # dict with keys ["user_id","salt",... ]

    def add_challenge(self, user_id: int, operation: str, challenge: bytes):
        self.ensure_connection()
        conn, cursor = self._get_connection()
        cursor.execute(
            "DELETE FROM pending_challenges WHERE user_id = %s AND operation = %s",
            (user_id, operation)
        )
        sql = """
            INSERT INTO pending_challenges
                (user_id, operation, challenge, created_at)
            VALUES (%s, %s, %s, UTC_TIMESTAMP())
        """
        cursor.execute(sql, (user_id, operation, challenge))
        conn.commit()

    def get_pending_challenge(self, user_id: int, operation: str, expiry_seconds: int = 300):
        self.ensure_connection()
        conn, cursor = self._get_connection()
        sql = """
            SELECT challenge, created_at
            FROM pending_challenges
            WHERE user_id = %s
              AND operation = %s
              AND created_at >= UTC_TIMESTAMP() - INTERVAL %s SECOND
            LIMIT 1
        """
        cursor.execute(sql, (user_id, operation, expiry_seconds))
        row = cursor.fetchone()
        if not row:
            logging.debug(f"No challenge found for user_id={user_id} operation={operation}")
            return None
        
        challenge = row['challenge']
        created_at = row['created_at']
        logging.debug(f"Found challenge for user_id={user_id} operation={operation}")
        logging.debug(f"Challenge created at: {created_at}")
        logging.debug(f"Current time: {datetime.datetime.utcnow()}")
        logging.debug(f"Challenge age: {(datetime.datetime.utcnow() - created_at).total_seconds()} seconds")
        return challenge

    def delete_challenge(self, user_id: int):
        self.ensure_connection()
        conn, cursor = self._get_connection()
        cursor.execute(
            "DELETE FROM pending_challenges WHERE user_id = %s",
            (user_id,)
        )
        conn.commit()

    def update_username(self, old_username: str, new_username: str):
        self.ensure_connection()
        conn, cursor = self._get_connection()
        sql = """
            UPDATE username_map
            SET username = %s
            WHERE username = %s
        """
        cursor.execute(sql, (new_username, old_username))
        conn.commit()

    def update_password(self, username: str, salt: bytes, opslimit: int, memlimit: int,
                        encrypted_privkey: bytes, privkey_nonce: bytes,
                        encrypted_kek: bytes, kek_nonce: bytes):
        self.ensure_connection()
        user_id = self._get_user_id(username)
        if user_id is None:
            raise ValueError(f"Unknown user '{username}'")
        conn, cursor = self._get_connection()
        sql = """
            UPDATE users
            SET salt               = %s,
                argon2_opslimit    = %s,
                argon2_memlimit    = %s,
                encrypted_privkey  = %s,
                privkey_nonce      = %s,
                encrypted_kek      = %s,
                kek_nonce          = %s
            WHERE id = %s
        """
        cursor.execute(sql, (
            salt,
            opslimit,
            memlimit,
            encrypted_privkey,
            privkey_nonce,
            encrypted_kek,
            kek_nonce,
            user_id
        ))
        conn.commit()

    def add_file(self, username: str, filename: str, encrypted_file: bytes, file_nonce: bytes,
                 encrypted_dek: bytes, dek_nonce: bytes):
        conn, cursor = self._get_connection()
        user_id = self._get_user_id(username)
        if user_id is None:
            raise ValueError(f"Unknown user '{username}'")
        sql = """
            INSERT INTO files
                (owner_id, filename, encrypted_file, file_nonce,
                 encrypted_dek, dek_nonce)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        cursor.execute(sql, (
            user_id,
            filename,
            encrypted_file,
            file_nonce,
            encrypted_dek,
            dek_nonce
        ))
        conn.commit()

    def list_files(self, username: str) -> List[dict]:
        conn, cursor = self._get_connection()
        user_id = self._get_user_id(username)
        if user_id is None:
            raise ValueError(f"Unknown user '{username}'")
        sql = """
            SELECT filename, id, created_at
            FROM files
            WHERE owner_id = %s
            ORDER BY created_at
        """
        cursor.execute(sql, (user_id,))
        rows = cursor.fetchall()
        if not rows:
            return []
        # Each row is a dict from DictCursor
        return [
            {
                "filename": row['filename'],
                "id": row['id'],
                "created_at": row['created_at'].isoformat()
            }
            for row in rows
        ]

    def get_file(self, username: str, filename: str):
        conn, cursor = self._get_connection()
        user_id = self._get_user_id(username)
        if user_id is None:
            raise ValueError(f"Unknown user '{username}'")
        sql = """
            SELECT encrypted_file, file_nonce, encrypted_dek, dek_nonce
            FROM files
            WHERE owner_id = %s
              AND filename = %s
            LIMIT 1
        """
        cursor.execute(sql, (user_id, filename))
        row = cursor.fetchone()
        if not row:
            return None
        return row  # dict with keys ["encrypted_file","file_nonce","encrypted_dek","dek_nonce"]

    def delete_file(self, username: str, filename: str):
        conn, cursor = self._get_connection()
        user_id = self._get_user_id(username)
        if user_id is None:
            raise ValueError(f"Unknown user '{username}'")
        sql = """
            DELETE FROM files
             WHERE owner_id = %s
               AND filename   = %s
            ORDER BY created_at DESC
            LIMIT 1
        """
        cursor.execute(sql, (user_id, filename))
        conn.commit()

    def add_pre_key_bundle(self, user_id: int, IK_pub: bytes, SPK_pub: bytes, SPK_signature: bytes):
        conn, cursor = self._get_connection()
        sql = """
            INSERT INTO pre_key_bundle
                (user_id, IK_pub, SPK_pub, SPK_signature)
            VALUES (%s, %s, %s, %s)
        """
        cursor.execute(sql, (user_id, IK_pub, SPK_pub, SPK_signature))
        conn.commit()

    def get_pre_key_bundle(self, user_id: int):
        conn, cursor = self._get_connection()
        sql = """
            SELECT IK_pub, SPK_pub, SPK_signature
            FROM pre_key_bundle
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 1
        """
        cursor.execute(sql, (user_id,))
        return cursor.fetchone()  # dict with keys ["IK_pub","SPK_pub","SPK_signature"]

    def get_highest_opk_id(self, user_id: int) -> int:
        """Get the highest opk_id for a user, or -1 if none exist."""
        self.ensure_connection()
        conn, cursor = self._get_connection()
        sql = """
            SELECT MAX(opk_id) as max_id
            FROM opks
            WHERE user_id = %s
        """
        cursor.execute(sql, (user_id,))
        row = cursor.fetchone()
        if not row or row['max_id'] is None:
            return -1
        return row['max_id']

    def add_opks(self, user_id: int, pre_keys: List[Tuple[int, bytes]]):
        """
        Add one-time pre-keys for a user.
        pre_keys: List of tuples (opk_id, pre_key_bytes).
        """
        self.ensure_connection()
        conn, cursor = self._get_connection()

        if not isinstance(pre_keys, list):
            raise ValueError("pre_keys must be a list")

        for opk_id, pre_key in pre_keys:
            if not isinstance(opk_id, int) or opk_id < 0:
                raise ValueError(f"Invalid opk_id: {opk_id}. Must be a non-negative integer.")
            if not isinstance(pre_key, bytes):
                raise ValueError("pre_key must be bytes")

        sql = """
            INSERT INTO opks
                (user_id, opk_id, pre_key)
            VALUES (%s, %s, %s)
        """
        for opk_id, pre_key in pre_keys:
            cursor.execute(sql, (user_id, opk_id, pre_key))
        conn.commit()

    def get_unused_opk(self, user_id: int):
        conn, cursor = self._get_connection()
        sql = """
            SELECT id, opk_id, pre_key
            FROM opks
            WHERE user_id = %s AND consumed = FALSE
            ORDER BY created_at ASC
            LIMIT 1
        """
        cursor.execute(sql, (user_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return row  # dict with keys ["id","opk_id","pre_key"]

    def mark_opk_consumed(self, id: int):
        conn, cursor = self._get_connection()
        sql = """
            UPDATE opks
            SET consumed = TRUE
            WHERE id = %s
        """
        cursor.execute(sql, (id,))
        conn.commit()

    def share_file(self, file_id: int, recipient_id: int, encrypted_file_key: bytes,
                   file_key_nonce: bytes, EK_pub: bytes, IK_pub: bytes, 
                   SPK_pub: bytes, SPK_signature: bytes, OPK_id: Optional[int] = None):
        conn, cursor = self._get_connection()
        sql = """
            INSERT INTO shared_files
                (file_id, recipient_id, encrypted_file_key, file_key_nonce,
                 EK_pub, IK_pub, SPK_pub, SPK_signature, OPK_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(sql, (
            file_id,
            recipient_id,
            encrypted_file_key,
            file_key_nonce,
            EK_pub,
            IK_pub,
            SPK_pub,
            SPK_signature,
            OPK_id
        ))
        conn.commit()

    def get_shared_files(self, username: str) -> List[Tuple]:
        """
        Get all files shared with the given user.
        Returns a list of dicts (share_id, id, filename, shared_by, created_at).
        """
        user_id = self._get_user_id(username)
        if user_id is None:
            return []
        conn, cursor = self._get_connection()
        sql = """
            SELECT s.share_id, f.id, f.filename, um.username as shared_by, f.created_at
            FROM shared_files s
            JOIN files f ON s.file_id = f.id
            JOIN username_map um ON f.owner_id = um.user_id
            WHERE s.recipient_id = %s
            ORDER BY f.created_at DESC
        """
        cursor.execute(sql, (user_id,))
        return cursor.fetchall()

    def get_shared_file_details(self, share_id: int):
        conn, cursor = self._get_connection()
        sql = """
            SELECT 
                sf.share_id,
                sf.file_id,
                sf.recipient_id,
                sf.EK_pub,
                sf.IK_pub,
                sf.SPK_pub,
                sf.SPK_signature,
                sf.encrypted_file_key,
                sf.OPK_id,
                sf.shared_at,
                f.filename
            FROM shared_files sf
            JOIN files f ON sf.file_id = f.id
            WHERE sf.share_id = %s
            LIMIT 1
        """
        cursor.execute(sql, (share_id,))
        return cursor.fetchone()

    def remove_shared_file(self, share_id: int):
        conn, cursor = self._get_connection()
        sql = """
            DELETE FROM shared_files
            WHERE share_id = %s
        """
        cursor.execute(sql, (share_id,))
        conn.commit()

    def add_tofu_backup(self, user_id: int, encrypted_data: bytes, backup_nonce: bytes):
        conn, cursor = self._get_connection()
        sql = """
            INSERT INTO tofu_backups
                (user_id, encrypted_data, backup_nonce)
            VALUES (%s, %s, %s)
        """
        cursor.execute(sql, (user_id, encrypted_data, backup_nonce))
        conn.commit()
        # Clean up old backups, keeping only the most recent one
        self.cleanup_old_tofu_backups(user_id, 1)

    def get_tofu_backup(self, user_id: int):
        conn, cursor = self._get_connection()
        sql = """
            SELECT encrypted_data, backup_nonce, created_at, last_verified
            FROM tofu_backups
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 1
        """
        cursor.execute(sql, (user_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "encrypted_data": row["encrypted_data"],
            "backup_nonce": row["backup_nonce"],
            "created_at": row["created_at"],
            "last_verified": row["last_verified"]
        }

    def get_all_users(self) -> list:
        """
        Get all users in the system as a list of (id, username).
        """
        conn, cursor = self._get_connection()
        sql = """
            SELECT u.id, m.username
            FROM users u
            JOIN username_map m ON u.id = m.user_id
            ORDER BY u.id
        """
        cursor.execute(sql)
        return cursor.fetchall()

    def get_file_id(self, username: str, filename: str) -> int:
        """
        Lookup the internal file ID for a given owner+filename.
        """
        conn, cursor = self._get_connection()
        user_id = self._get_user_id(username)
        if user_id is None:
            raise ValueError(f"Unknown user '{username}'")
        sql = """
            SELECT id
            FROM files
            WHERE owner_id = %s
              AND filename = %s
            LIMIT 1
        """
        cursor.execute(sql, (user_id, filename))
        row = cursor.fetchone()
        if not row:
            return None
        return row["id"]

    def get_shared_files_to(self, owner_id: int, recipient_id: int):
        """
        Files that owner_id has shared to recipient_id.
        """
        conn, cursor = self._get_connection()
        sql = """
            SELECT sf.share_id, sf.file_id, f.filename,
                   sf.EK_pub, sf.IK_pub, sf.encrypted_file_key, sf.shared_at
            FROM shared_files sf
            JOIN files f ON sf.file_id = f.id
            WHERE f.owner_id    = %s
              AND sf.recipient_id = %s
            ORDER BY sf.shared_at DESC
        """
        cursor.execute(sql, (owner_id, recipient_id))
        return cursor.fetchall()

    def get_shared_files_from(self, recipient_id: int, owner_id: int):
        """
        Files that owner_id has shared to recipient_id (i.e., shared *from* owner_id *to* me).
        """
        conn, cursor = self._get_connection()
        sql = """
            SELECT sf.share_id, sf.file_id, f.filename,
                   sf.EK_pub, sf.IK_pub, sf.encrypted_file_key, sf.shared_at
            FROM shared_files sf
            JOIN files f ON sf.file_id = f.id
            WHERE sf.recipient_id = %s
              AND f.owner_id      = %s
            ORDER BY sf.shared_at DESC
        """
        cursor.execute(sql, (recipient_id, owner_id))
        return cursor.fetchall()

    def cleanup_old_tofu_backups(self, user_id: int, keep_last_n: int = 1):
        conn, cursor = self._get_connection()
        sql = """
            DELETE FROM tofu_backups 
            WHERE user_id = %s 
              AND id NOT IN (
                  SELECT id FROM (
                      SELECT id 
                      FROM tofu_backups 
                      WHERE user_id = %s 
                      ORDER BY created_at DESC 
                      LIMIT %s
                  ) as latest
              )
        """
        cursor.execute(sql, (user_id, user_id, keep_last_n))
        conn.commit()

    def retrieve_file_dek(self, file_id: int):
        conn, cursor = self._get_connection()
        sql = """
            SELECT encrypted_dek, dek_nonce
            FROM files
            WHERE id = %s
        """
        cursor.execute(sql, (file_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "encrypted_dek": row["encrypted_dek"],
            "dek_nonce": row["dek_nonce"]
        }

    def get_file_owner(self, file_id: int) -> int:
        """
        Get the owner ID of a file.
        """
        conn, cursor = self._get_connection()
        sql = """
            SELECT owner_id
            FROM files
            WHERE id = %s
            LIMIT 1
        """
        cursor.execute(sql, (file_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return row["owner_id"]

    def get_shared_file(self, share_id: int, recipient_id: int):
        """
        Fetch a shared file record (with encryption info) for a specific recipient.
        """
        conn, cursor = self._get_connection()
        sql = """
            SELECT 
                f.id as file_id,
                f.encrypted_file,
                f.file_nonce,
                sf.encrypted_file_key,
                sf.file_key_nonce,
                sf.EK_pub,
                sf.IK_pub,
                sf.SPK_pub,
                sf.SPK_signature,
                sf.OPK_id
            FROM shared_files sf
            JOIN files f ON sf.file_id = f.id
            WHERE sf.share_id = %s
              AND sf.recipient_id = %s
            LIMIT 1
        """
        cursor.execute(sql, (share_id, recipient_id))
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "file_id": row["file_id"],
            "encrypted_file": row["encrypted_file"],
            "file_nonce": row["file_nonce"],
            "encrypted_file_key": row["encrypted_file_key"],
            "file_key_nonce": row["file_key_nonce"],
            "EK_pub": row["EK_pub"],
            "IK_pub": row["IK_pub"],
            "SPK_pub": row["SPK_pub"],
            "SPK_signature": row["SPK_signature"],
            "OPK_id": row["OPK_id"]
        }

    def get_file_nonce(self, file_id: int) -> bytes:
        conn, cursor = self._get_connection()
        sql = "SELECT file_nonce FROM files WHERE id = %s"
        cursor.execute(sql, (file_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return row["file_nonce"]

    def get_matching_users(self, search_query: str) -> list:
        """
        Get all users whose usernames match the given search query.
        """
        self.ensure_connection()
        conn, cursor = self._get_connection()
        
        # Escape wildcards
        sanitized_query = search_query.replace('%', '\\%').replace('_', '\\_')
        sql = """
            SELECT u.id, m.username
            FROM users u
            JOIN username_map m ON u.id = m.user_id
            WHERE m.username LIKE %s
            ORDER BY m.username
            LIMIT 50
        """
        search_pattern = f"%{sanitized_query}%"
        cursor.execute(sql, (search_pattern,))
        return cursor.fetchall()

    def get_sharers(self, recipient_id: int) -> list:
        """
        Return a list of all distinct usernames who have shared at least one file to recipient_id.
        """
        self.ensure_connection()
        conn, cursor = self._get_connection()
        sql = """
            SELECT DISTINCT um.username
            FROM shared_files sf
            JOIN files f ON sf.file_id = f.id
            JOIN username_map um ON f.owner_id = um.user_id
            WHERE sf.recipient_id = %s
        """
        cursor.execute(sql, (recipient_id,))
        rows = cursor.fetchall()
        if not rows:
            return []
        return [row["username"] for row in rows]

    def get_file_by_id(self, file_id: int):
        """
        Fetch the full file record (encrypted_file, file_nonce, encrypted_dek, dek_nonce, owner_id, filename)
        by its internal ID.
        """
        self.ensure_connection()
        conn, cursor = self._get_connection()
        sql = """
            SELECT owner_id, filename, encrypted_file, file_nonce, encrypted_dek, dek_nonce
            FROM files
            WHERE id = %s
            LIMIT 1
        """
        cursor.execute(sql, (file_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "owner_id": row["owner_id"],
            "filename": row["filename"],
            "encrypted_file": row["encrypted_file"],
            "file_nonce": row["file_nonce"],
            "encrypted_dek": row["encrypted_dek"],
            "dek_nonce": row["dek_nonce"]
        }

    def delete_file_by_id(self, file_id: int, username: str):
        """
        Delete a file by its ID, after confirming that `username` is the owner.
        """
        self.ensure_connection()
        user_id = self._get_user_id(username)
        if user_id is None:
            raise ValueError(f"Unknown user '{username}'")
        conn, cursor = self._get_connection()
        sql = """
            DELETE FROM files
            WHERE id = %s
              AND owner_id = %s
        """
        cursor.execute(sql, (file_id, user_id))
        conn.commit()

    def clear_user_opks(self, user_id: int) -> None:
        """Clear all OPKs for a user. For testing purposes only."""
        conn, cursor = self._get_connection()
        sql = "DELETE FROM opks WHERE user_id = %s"
        cursor.execute(sql, (user_id,))
        conn.commit()

    def get_unused_opk_count(self, user_id: int) -> int:
        """Get the count of unused OPKs for a user."""
        conn, cursor = self._get_connection()
        sql = """
            SELECT COUNT(*) as count
            FROM opks
            WHERE user_id = %s AND consumed = FALSE
        """
        cursor.execute(sql, (user_id,))
        row = cursor.fetchone()
        return row['count'] if row else 0

    def get_shared_files_for_file(self, file_id: int):
        """
        Get all shared file entries for a specific file.
        """
        conn, cursor = self._get_connection()
        sql = """
            SELECT 
                sf.share_id,
                sf.recipient_id,
                sf.EK_pub,
                sf.IK_pub,
                sf.SPK_pub,
                sf.SPK_signature,
                sf.encrypted_file_key,
                sf.file_key_nonce,
                sf.OPK_id,
                um.username as recipient_username
            FROM shared_files sf
            JOIN username_map um ON sf.recipient_id = um.user_id
            WHERE sf.file_id = %s
        """
        cursor.execute(sql, (file_id,))
        return cursor.fetchall()

    def update_shared_file_entry(self, share_id: int, encrypted_file_key: bytes,
                               file_key_nonce: bytes, EK_pub: bytes, IK_pub: bytes,
                               SPK_pub: bytes, SPK_signature: bytes, OPK_id: Optional[int] = None):
        """
        Update a shared file entry with new encryption parameters.
        """
        conn, cursor = self._get_connection()
        sql = """
            UPDATE shared_files
            SET encrypted_file_key = %s,
                file_key_nonce = %s,
                EK_pub = %s,
                IK_pub = %s,
                SPK_pub = %s,
                SPK_signature = %s,
                OPK_id = %s
            WHERE share_id = %s
        """
        cursor.execute(sql, (
            encrypted_file_key,
            file_key_nonce,
            EK_pub,
            IK_pub,
            SPK_pub,
            SPK_signature,
            OPK_id,
            share_id
        ))
        conn.commit()

    def remove_shared_file_access(self, share_id: int):
        """
        Remove a shared file entry.
        """
        conn, cursor = self._get_connection()
        sql = """
            DELETE FROM shared_files
            WHERE share_id = %s
        """
        cursor.execute(sql, (share_id,))
        conn.commit()

