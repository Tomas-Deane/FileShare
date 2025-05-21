#!/usr/bin/env python3
import os
import sys

import pymysql as connector

# Database connection parameters (will use env variables))
DB_USER     = os.environ.get('DB_USER',     'nrmc')
DB_PASSWORD = os.environ.get('DB_PASSWORD', 'nrmc')
DB_HOST     = os.environ.get('DB_HOST',     '127.0.0.1')
DB_PORT     = int(os.environ.get('DB_PORT', '3306'))
DB_NAME     = os.environ.get('DB_NAME',     'nrmc')

def init_db():
    """
    Initialize the users table in the MySQL database if it doesn't already exist.
    """
    conn = connector.connect(
        user     = DB_USER,
        password = DB_PASSWORD,
        host     = DB_HOST,
        port     = DB_PORT,
        database = DB_NAME
    )
    cursor = conn.cursor()
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
    conn.commit()
    cursor.close()
    conn.close()

class UserDB:
    """
    Simple wrapper around the MySQL users table.
    """
    def __init__(self):
        self.conn = connector.connect(
            user     = DB_USER,
            password = DB_PASSWORD,
            host     = DB_HOST,
            port     = DB_PORT,
            database = DB_NAME
        )
        # If the connector supports dictionary cursors, use one
        try:
            self.cursor = self.conn.cursor(dictionary=True)
        except TypeError:
            # fallback to regular cursor (will return tuples)
            self.cursor = self.conn.cursor()

    def add_user(self, username, salt, opslimit, memlimit,
                 public_key, encrypted_privkey, privkey_nonce):
        """
        Insert a new user record.
        """
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
        """
        Retrieve a user record by username, or None if not found.
        Always returns a dict with keys:
          'username', 'salt', 'argon2_opslimit', 'argon2_memlimit',
          'public_key', 'encrypted_privkey', 'privkey_nonce'
        """
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
        if row is None:
            return None

        # If we already have a dict (dictionary=True), just return it
        if isinstance(row, dict):
            return row

        # Otherwise we got a tuple: map column names to row values
        columns = [col[0] for col in self.cursor.description]
        return dict(zip(columns, row))