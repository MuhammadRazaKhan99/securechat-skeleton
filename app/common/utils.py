# app/common/utils.py
import base64, hashlib, time, os
from typing import Tuple

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode()

def ub64(s: str) -> bytes:
    return base64.b64decode(s)

def now_ms() -> int:
    return int(time.time() * 1000)

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def random_bytes(n: int) -> bytes:
    return os.urandom(n)
