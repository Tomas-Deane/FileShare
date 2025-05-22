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
    Initialize the users table and pending_challenges table in the MySQL database
    if they don't already exist.
    """
    conn = connector.connect(
        user     = DB_USER,
        password = DB_PASSWORD,
        host     = DB_HOST,
        port     = DB_PORT,
        database = DB_NAME
    )
    cursor = conn.cursor()
    # Users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username           VARCHAR(255)        PRIMARY KEY,
        salt               BLOB                NOT NULL,
        argon2_opslimit    INT                 NOT NULL,
        argon2_memlimit    INT                 NOT NULL,
        public_key         BLOB                NOT NULL,
        encrypted_privkey  BLOB                NOT NULL,
        privkey_nonce      BLOB                NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)

    # Pending challenges for stateless login
    # Use VARBINARY(32) so we can index the exact-length challenge
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS pending_challenges (
        id          INT              AUTO_INCREMENT PRIMARY KEY,
        username    VARCHAR(255)     NOT NULL,
        challenge   VARBINARY(32)    NOT NULL,
        created_at  DATETIME         NOT NULL,
        FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE,
        UNIQUE KEY uq_user_challenge (username, challenge)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)

    conn.commit()
    cursor.close()
    conn.close()

class UserDB:
    """
    Simple wrapper around the MySQL users and pending_challenges tables.
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

    def add_user(self, username, salt, opslimit, memlimit,
                 public_key, encrypted_privkey, privkey_nonce):
        sql = """
            INSERT INTO users
                (username, salt, argon2_opslimit, argon2_memlimit,
                 public_key, encrypted_privkey, privkey_nonce)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        self.cursor.execute(sql, (
            username,
            salt,
            opslimit,
            memlimit,
            public_key,
            encrypted_privkey,
            privkey_nonce
        ))
        self.conn.commit()

    def get_user(self, username):
        sql = """
            SELECT
              username,
              salt,
              argon2_opslimit    AS argon2_opslimit,
              argon2_memlimit    AS argon2_memlimit,
              public_key,
              encrypted_privkey,
              privkey_nonce
            FROM users
            WHERE username = %s
        """
        self.cursor.execute(sql, (username,))
        row = self.cursor.fetchone()
        if not row:
            return None
        if isinstance(row, dict):
            return row
        columns = [col[0] for col in self.cursor.description]
        return dict(zip(columns, row))

    def add_challenge(self, username, challenge: bytes):
        # Remove any existing challenges for this user
        self.cursor.execute(
            "DELETE FROM pending_challenges WHERE username = %s",
            (username,)
        )
        sql = """
            INSERT INTO pending_challenges (username, challenge, created_at)
            VALUES (%s, %s, UTC_TIMESTAMP())
        """
        self.cursor.execute(sql, (username, challenge))
        self.conn.commit()

    def get_pending_challenge(self, username, expiry_seconds=300):
        sql = """
            SELECT challenge
            FROM pending_challenges
            WHERE username = %s
              AND created_at >= UTC_TIMESTAMP() - INTERVAL %s SECOND
            LIMIT 1
        """
        self.cursor.execute(sql, (username, expiry_seconds))
        row = self.cursor.fetchone()
        if not row:
            return None
        return row['challenge'] if isinstance(row, dict) else row[0]

    def delete_challenge(self, username):
        self.cursor.execute(
            "DELETE FROM pending_challenges WHERE username = %s",
            (username,)
        )
        self.conn.commit()

