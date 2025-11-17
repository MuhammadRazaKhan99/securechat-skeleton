"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation.""" 
raise NotImplementedError("students: implement DH helpers")
# app/crypto/dh.py
import hashlib

def derive_aes_key_from_shared(shared_int: int) -> bytes:
    # big-endian bytes of shared_int
    b = shared_int.to_bytes((shared_int.bit_length() + 7) // 8 or 1, "big")
    h = hashlib.sha256(b).digest()
    return h[:16]  # truncate to 16 bytes (AES-128)

def compute_public(g: int, p: int, priv: int) -> int:
    return pow(g, priv, p)

def compute_shared(their_pub: int, p: int, priv: int) -> int:
    return pow(their_pub, priv, p)
