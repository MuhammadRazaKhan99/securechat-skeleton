"""MySQL users table + salted hashing (no chat storage).""" 
raise NotImplementedError("students: implement DB layer")
# app/storage/db.py
import pymysql
import os
import argparse
from app.common.utils import sha256_hex, random_bytes
from binascii import hexlify, unhexlify

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_USER = os.getenv("DB_USER", "scuser")
DB_PASS = os.getenv("DB_PASS", "scpass")
DB_NAME = os.getenv("DB_NAME", "securechat")
DB_PORT = int(os.getenv("DB_PORT", "3306"))

def get_conn():
    return pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, db=DB_NAME, port=DB_PORT)

def init_db():
    c = get_conn()
    with c.cursor() as cur:
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email VARCHAR(255) PRIMARY KEY,
            username VARCHAR(255) UNIQUE,
            salt VARBINARY(16),
            pwd_hash CHAR(64)
        )""")
        c.commit()
    print("DB initialized")

def create_user(email: str, username: str, password: str) -> bool:
    salt = random_bytes(16)
    pwd_hash = sha256_hex(salt + password.encode())
    c = get_conn()
    try:
        with c.cursor() as cur:
            cur.execute("INSERT INTO users(email, username, salt, pwd_hash) VALUES(%s,%s,%s,%s)",
                        (email, username, salt, pwd_hash))
            c.commit()
        return True
    except Exception as e:
        print("DB insert error:", e)
        return False

def verify_user(email: str, password: str):
    c = get_conn()
    with c.cursor() as cur:
        cur.execute("SELECT salt, pwd_hash FROM users WHERE email=%s", (email,))
        row = cur.fetchone()
        if not row:
            return False
        salt, stored = row[0], row[1]
        computed = sha256_hex(salt + password.encode())
        # constant time compare
        return computed == stored

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--init", action="store_true")
    args = parser.parse_args()
    if args.init:
        init_db()
