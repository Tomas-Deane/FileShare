# cloud/models.py
#!/usr/bin/env python3
import os
import pymysql as connector
import logging
import datetime
from typing import List, Tuple

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
        database = DB_NAME
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
        pre_key             BLOB                NOT NULL,
        consumed            BOOLEAN             NOT NULL DEFAULT FALSE,
        created_at          DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_opks_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,
        INDEX idx_user_consumed (user_id, consumed)
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
        encrypted_file_key   BLOB                NOT NULL,
        OPK_id              BIGINT              NOT NULL,
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
        encrypted_data      LONGBLOB            NOT NULL,  -- Encrypted backup data
        backup_nonce        BLOB                NOT NULL,  -- Nonce for encrypted_data
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
    Wrapper around users, username_map, pending_challenges, and files tables,
    with automatic reconnect on lost connection.
    """
    def __init__(self):
        self._connect()

    def _connect(self):
        self.conn = connector.connect(
            user     = DB_USER,
            password = DB_PASSWORD,
            host     = DB_HOST,
            port     = DB_PORT,
            database = DB_NAME,
            autocommit=False
        )
        try:
            self.cursor = self.conn.cursor(dictionary=True)
        except TypeError:
            self.cursor = self.conn.cursor()

    def ensure_connection(self):
        try:
            # ping with reconnect=True will re-open if needed
            self.conn.ping(reconnect=True)
        except Exception:
            # if ping fails entirely, re-establish
            self._connect()

    def _get_user_id(self, username):
        self.ensure_connection()
        sql = "SELECT user_id FROM username_map WHERE username = %s"
        self.cursor.execute(sql, (username,))
        row = self.cursor.fetchone()
        if not row:
            return None
        return row['user_id'] if isinstance(row, dict) else row[0]

    def add_user(self, username, salt, opslimit, memlimit,
                 public_key, encrypted_privkey, privkey_nonce,
                 encrypted_kek, kek_nonce):
        self.ensure_connection()
        sql_user = """
            INSERT INTO users
                (salt, argon2_opslimit, argon2_memlimit,
                 public_key, encrypted_privkey, privkey_nonce,
                 encrypted_kek, kek_nonce)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        self.cursor.execute(sql_user, (
            salt,
            opslimit,
            memlimit,
            public_key,
            encrypted_privkey,
            privkey_nonce,
            encrypted_kek,
            kek_nonce
        ))
        user_id = self.cursor.lastrowid

        sql_map = "INSERT INTO username_map (username, user_id) VALUES (%s, %s)"
        self.cursor.execute(sql_map, (username, user_id))
        self.conn.commit()
        return user_id

    def get_user(self, username):
        self.ensure_connection()
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
        self.cursor.execute(sql, (username,))
        row = self.cursor.fetchone()
        if not row:
            return None
        if isinstance(row, dict):
            return row
        columns = [col[0] for col in self.cursor.description]
        return dict(zip(columns, row))

    def add_challenge(self, user_id, operation, challenge: bytes):
        self.ensure_connection()
        self.cursor.execute(
            "DELETE FROM pending_challenges WHERE user_id = %s AND operation = %s",
            (user_id, operation)
        )
        sql = """
            INSERT INTO pending_challenges
                (user_id, operation, challenge, created_at)
            VALUES (%s, %s, %s, UTC_TIMESTAMP())
        """
        self.cursor.execute(sql, (user_id, operation, challenge))
        self.conn.commit()

    def get_pending_challenge(self, user_id, operation, expiry_seconds=300):
        self.ensure_connection()
        sql = """
            SELECT challenge, created_at
            FROM pending_challenges
            WHERE user_id = %s
              AND operation = %s
              AND created_at >= UTC_TIMESTAMP() - INTERVAL %s SECOND
            LIMIT 1
        """
        self.cursor.execute(sql, (user_id, operation, expiry_seconds))
        row = self.cursor.fetchone()
        if not row:
            logging.debug(f"No challenge found for user_id={user_id} operation={operation}")
            return None
        
        challenge = row['challenge'] if isinstance(row, dict) else row[0]
        created_at = row['created_at'] if isinstance(row, dict) else row[1]
        logging.debug(f"Found challenge for user_id={user_id} operation={operation}")
        logging.debug(f"Challenge created at: {created_at}")
        logging.debug(f"Current time: {datetime.datetime.utcnow()}")
        logging.debug(f"Challenge age: {(datetime.datetime.utcnow() - created_at).total_seconds()} seconds")
        return challenge

    def delete_challenge(self, user_id):
        self.ensure_connection()
        self.cursor.execute(
            "DELETE FROM pending_challenges WHERE user_id = %s",
            (user_id,)
        )
        self.conn.commit()

    def update_username(self, old_username, new_username):
        self.ensure_connection()
        sql = """
            UPDATE username_map
            SET username = %s
            WHERE username = %s
        """
        self.cursor.execute(sql, (new_username, old_username))
        self.conn.commit()

    def update_password(self, username, salt, opslimit, memlimit,
                        encrypted_privkey, privkey_nonce,
                        encrypted_kek, kek_nonce):
        self.ensure_connection()
        user_id = self._get_user_id(username)
        if user_id is None:
            raise ValueError(f"Unknown user '{username}'")
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
        self.cursor.execute(sql, (
            salt,
            opslimit,
            memlimit,
            encrypted_privkey,
            privkey_nonce,
            encrypted_kek,
            kek_nonce,
            user_id
        ))
        self.conn.commit()

    def add_file(self, username, filename, encrypted_file, file_nonce,
                 encrypted_dek, dek_nonce):
        self.ensure_connection()
        user_id = self._get_user_id(username)
        if user_id is None:
            raise ValueError(f"Unknown user '{username}'")
        sql = """
            INSERT INTO files
                (owner_id, filename, encrypted_file, file_nonce,
                 encrypted_dek, dek_nonce)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        self.cursor.execute(sql, (
            user_id,
            filename,
            encrypted_file,
            file_nonce,
            encrypted_dek,
            dek_nonce
        ))
        self.conn.commit()

    def list_files(self, username):
        self.ensure_connection()
        user_id = self._get_user_id(username)
        if user_id is None:
            raise ValueError(f"Unknown user '{username}'")
        sql = """
            SELECT filename, id, created_at
            FROM files
            WHERE owner_id = %s
            ORDER BY created_at
        """
        self.cursor.execute(sql, (user_id,))
        rows = self.cursor.fetchall()
        if not rows:
            return []
        if isinstance(rows[0], dict):
            return [{"filename": row['filename'], "id": row['id'], "created_at": row['created_at'].isoformat()} for row in rows]
        else:
            return [{"filename": row[0], "id": row[1], "created_at": row[2].isoformat()} for row in rows]

    def get_file(self, username, filename):
        self.ensure_connection()
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
        self.cursor.execute(sql, (user_id, filename))
        row = self.cursor.fetchone()
        if not row:
            return None
        if isinstance(row, dict):
            return row
        columns = [col[0] for col in self.cursor.description]
        return dict(zip(columns, row))

    def delete_file(self, username, filename):
        self.ensure_connection()
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
        self.cursor.execute(sql, (user_id, filename))
        self.conn.commit()

    def add_pre_key_bundle(self, user_id, IK_pub, SPK_pub, SPK_signature):
        self.ensure_connection()
        sql = """
            INSERT INTO pre_key_bundle
                (user_id, IK_pub, SPK_pub, SPK_signature)
            VALUES (%s, %s, %s, %s)
        """
        self.cursor.execute(sql, (user_id, IK_pub, SPK_pub, SPK_signature))
        self.conn.commit()

    def get_pre_key_bundle(self, user_id):
        self.ensure_connection()
        sql = """
            SELECT IK_pub, SPK_pub, SPK_signature
            FROM pre_key_bundle
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 1
        """
        self.cursor.execute(sql, (user_id,))
        return self.cursor.fetchone()

    def add_opks(self, user_id, pre_keys):
        self.ensure_connection()
        sql = """
            INSERT INTO opks
                (user_id, pre_key)
            VALUES (%s, %s)
        """
        for pre_key in pre_keys:
            self.cursor.execute(sql, (user_id, pre_key))
        self.conn.commit()

    def get_unused_opk(self, user_id):
        self.ensure_connection()
        sql = """
            SELECT id, pre_key
            FROM opks
            WHERE user_id = %s AND consumed = FALSE
            ORDER BY created_at ASC
            LIMIT 1
        """
        self.cursor.execute(sql, (user_id,))
        return self.cursor.fetchone()

    def mark_opk_consumed(self, opk_id):
        self.ensure_connection()
        sql = """
            UPDATE opks
            SET consumed = TRUE
            WHERE id = %s
        """
        self.cursor.execute(sql, (opk_id,))
        self.conn.commit()

    def share_file(self, file_id, recipient_id, EK_pub, IK_pub, encrypted_file_key, OPK_id):
        self.ensure_connection()
        sql = """
            INSERT INTO shared_files
                (file_id, recipient_id, EK_pub, IK_pub, encrypted_file_key, OPK_id)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        self.cursor.execute(sql, (file_id, recipient_id, EK_pub, IK_pub, encrypted_file_key, OPK_id))
        self.conn.commit()

    def get_shared_files(self, username: str) -> List[Tuple]:
        """Get all files shared with the given user."""
        # First get the user's ID
        user_id = self._get_user_id(username)
        if user_id is None:
            return []
        
        query = """
            SELECT s.share_id, f.id, f.filename, um.username as shared_by, f.created_at
            FROM shared_files s
            JOIN files f ON s.file_id = f.id
            JOIN username_map um ON f.owner_id = um.user_id
            WHERE s.recipient_id = %s
            ORDER BY f.created_at DESC
        """
        cursor = self.conn.cursor()
        try:
            cursor.execute(query, (user_id,))
            return cursor.fetchall()
        finally:
            cursor.close()

    def get_shared_file_details(self, share_id):
        self.ensure_connection()
        sql = """
            SELECT 
                sf.share_id,
                sf.file_id,
                sf.recipient_id,
                sf.EK_pub,
                sf.IK_pub,
                sf.encrypted_file_key,
                sf.OPK_id,
                sf.shared_at,
                f.filename
            FROM shared_files sf
            JOIN files f ON sf.file_id = f.id
            WHERE sf.share_id = %s
            LIMIT 1
        """
        self.cursor.execute(sql, (share_id,))
        return self.cursor.fetchone()

    def remove_shared_file(self, share_id):
        self.ensure_connection()
        sql = """
            DELETE FROM shared_files
            WHERE share_id = %s
        """
        self.cursor.execute(sql, (share_id,))
        self.conn.commit()

    def add_tofu_backup(self, user_id: int, encrypted_data: bytes, backup_nonce: bytes):
        self.ensure_connection()
        sql = """
            INSERT INTO tofu_backups
                (user_id, encrypted_data, backup_nonce)
            VALUES (%s, %s, %s)
        """
        self.cursor.execute(sql, (
            user_id,
            encrypted_data,
            backup_nonce
        ))
        self.conn.commit()
        
        # Clean up old backups, keeping only the most recent one
        self.cleanup_old_tofu_backups(user_id, 1)

    def get_tofu_backup(self, user_id: int):
        self.ensure_connection()
        sql = """
            SELECT encrypted_data, backup_nonce, created_at, last_verified
            FROM tofu_backups
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 1
        """
        self.cursor.execute(sql, (user_id,))
        row = self.cursor.fetchone()
        if not row:
            return None
        
        # Convert tuple to dictionary
        if isinstance(row, dict):
            return row
        else:
            return {
                "encrypted_data": row[0],
                "backup_nonce": row[1],
                "created_at": row[2],
                "last_verified": row[3]
            }

    def get_all_users(self) -> list:
        """Get all users in the system."""
        self.ensure_connection()
        sql = """
            SELECT u.id, m.username
            FROM users u
            JOIN username_map m ON u.id = m.user_id
            ORDER BY u.id
        """
        self.cursor.execute(sql)
        return self.cursor.fetchall()
    
    def get_file_id(self, username: str, filename: str) -> int:
         """Lookup the internal file ID for a given owner+filename."""
         self.ensure_connection()
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
         self.cursor.execute(sql, (user_id, filename))
         row = self.cursor.fetchone()
         if not row:
             return None
         return row['id'] if isinstance(row, dict) else row[0]

    def get_shared_files_to(self, owner_id: int, recipient_id: int):
        """Files *I* (owner_id) have shared *to* recipient_id."""
        self.ensure_connection()
        sql = """
            SELECT sf.share_id, sf.file_id, f.filename,
                sf.EK_pub, sf.IK_pub, sf.encrypted_file_key, sf.shared_at
            FROM shared_files sf
            JOIN files f ON sf.file_id = f.id
            WHERE f.owner_id    = %s
            AND sf.recipient_id = %s
            ORDER BY sf.shared_at DESC
        """
        self.cursor.execute(sql, (owner_id, recipient_id))
        return self.cursor.fetchall()

    def get_shared_files_from(self, recipient_id: int, owner_id: int):
        """Files that owner_id has shared *to* me (recipient_id)."""
        self.ensure_connection()
        sql = """
            SELECT sf.share_id, sf.file_id, f.filename,
                sf.EK_pub, sf.IK_pub, sf.encrypted_file_key, sf.shared_at
            FROM shared_files sf
            JOIN files f ON sf.file_id = f.id
            WHERE sf.recipient_id = %s
            AND f.owner_id      = %s
            ORDER BY sf.shared_at DESC
        """
        self.cursor.execute(sql, (recipient_id, owner_id))
        return self.cursor.fetchall()

    def cleanup_old_tofu_backups(self, user_id: int, keep_last_n: int = 1):
        self.ensure_connection()
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
        self.cursor.execute(sql, (user_id, user_id, keep_last_n))
        self.conn.commit()

    def retrieve_file_dek(self, file_id: int):
        self.ensure_connection()
        sql = """
            SELECT encrypted_dek, dek_nonce
            FROM files
            WHERE id = %s
        """
        self.cursor.execute(sql, (file_id,))
        row = self.cursor.fetchone()
        if not row:
            return None
        if isinstance(row, dict):
            return row
        columns = [col[0] for col in self.cursor.description]
        return dict(zip(columns, row))

    def get_file_owner(self, file_id: int) -> int | None:
        """Get the owner ID of a file."""
        self.ensure_connection()
        sql = """
            SELECT owner_id
            FROM files
            WHERE id = %s
            LIMIT 1
        """
        self.cursor.execute(sql, (file_id,))
        row = self.cursor.fetchone()
        if not row:
            return None
        return row['owner_id'] if isinstance(row, dict) else row[0]


