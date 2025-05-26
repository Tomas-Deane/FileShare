#!/usr/bin/env python3
import os
import pymysql as connector

# Database connection parameters (will use env variables)
DB_USER     = os.environ.get('DB_USER',     'nrmc')
DB_PASSWORD = os.environ.get('DB_PASSWORD', 'nrmc')
DB_HOST     = os.environ.get('DB_HOST',     '127.0.0.1')
DB_PORT     = int(os.environ.get('DB_PORT', '3306'))
DB_NAME     = os.environ.get('DB_NAME',     'nrmc')


def init_db():
    """
    Ensure the users, username_map, pending_challenges, and files tables
    all exist.  Any that are already there will be left intact.
    """
    conn = connector.connect(
        user     = DB_USER,
        password = DB_PASSWORD,
        host     = DB_HOST,
        port     = DB_PORT,
        database = DB_NAME
    )
    cursor = conn.cursor()

    # 1) users: crypto data, PK = auto-inc id
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

    # 2) username_map: maps username → users.id
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

    # 3) pending_challenges: by user_id + operation
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

    # 4) files: store encrypted files and DEKs
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

    conn.commit()
    cursor.close()
    conn.close()


class UserDB:
    """
    Wrapper around users, username_map, pending_challenges, and files tables.
    """
    def __init__(self):
        self.conn = connector.connect(
            user     = DB_USER,
            password = DB_PASSWORD,
            host     = DB_HOST,
            port     = DB_PORT,
            database = DB_NAME
        )
        try:
            self.cursor = self.conn.cursor(dictionary=True)
        except TypeError:
            self.cursor = self.conn.cursor()

    def _get_user_id(self, username):
        """
        Return integer user_id for a username, or None if absent.
        """
        sql = "SELECT user_id FROM username_map WHERE username = %s"
        self.cursor.execute(sql, (username,))
        row = self.cursor.fetchone()
        if not row:
            return None
        return row['user_id'] if isinstance(row, dict) else row[0]

    def add_user(self, username, salt, opslimit, memlimit,
                 public_key, encrypted_privkey, privkey_nonce,
                 encrypted_kek, kek_nonce):
        """
        Insert crypto data, get new id, then map username→id.
        """
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

    def get_user(self, username):
        """
        JOIN username_map→users. Always returns a dict with:
        user_id, salt, argon2_opslimit, argon2_memlimit,
        public_key, encrypted_privkey, privkey_nonce,
        encrypted_kek, kek_nonce or None if not found.
        """
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
        sql = """
            SELECT challenge
            FROM pending_challenges
            WHERE user_id = %s
              AND operation = %s
              AND created_at >= UTC_TIMESTAMP() - INTERVAL %s SECOND
            LIMIT 1
        """
        self.cursor.execute(sql, (user_id, operation, expiry_seconds))
        row = self.cursor.fetchone()
        if not row:
            return None
        return row['challenge'] if isinstance(row, dict) else row[0]

    def delete_challenge(self, user_id):
        self.cursor.execute(
            "DELETE FROM pending_challenges WHERE user_id = %s",
            (user_id,)
        )
        self.conn.commit()

    def update_username(self, old_username, new_username):
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
        """
        Overwrite crypto fields for password + KEK envelope.
        """
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
        """
        Store a new encrypted file record for the given user.
        """
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
        """
        Return a list of filenames owned by the given user, ordered by creation time.
        """
        user_id = self._get_user_id(username)
        if user_id is None:
            raise ValueError(f"Unknown user '{username}'")

        sql = """
            SELECT filename
            FROM files
            WHERE owner_id = %s
            ORDER BY created_at
        """
        self.cursor.execute(sql, (user_id,))
        rows = self.cursor.fetchall()
        if not rows:
            return []
        if isinstance(rows[0], dict):
            return [row['filename'] for row in rows]
        else:
            return [row[0] for row in rows]

    def get_file(self, username, filename):
        """
        Return the encrypted_file, file_nonce, encrypted_dek, and dek_nonce for the specified file.
        """
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
        """
        Delete *one* file record (and its DEK) for the given user.
        If you’ve ever uploaded the same filename multiple times, this
        will only remove one instance at a time.
        """
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