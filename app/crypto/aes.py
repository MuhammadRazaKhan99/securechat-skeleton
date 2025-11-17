"""AES-128(ECB)+PKCS#7 helpers (use library).""" 
raise NotImplementedError("students: implement AES helpers")
# app/crypto/aes.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from typing import Tuple

BLOCK = 16

def pkcs7_pad(data: bytes) -> bytes:
    padder = padding.PKCS7(8 * BLOCK).padder()
    return padder.update(data) + padder.finalize()

def pkcs7_unpad(data: bytes) -> bytes:
    unpadder = padding.PKCS7(8 * BLOCK).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def aes_encrypt_ecb(key16: bytes, plaintext: bytes) -> bytes:
    assert len(key16) == 16
    pt = pkcs7_pad(plaintext)
    cipher = Cipher(algorithms.AES(key16), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(pt) + encryptor.finalize()

def aes_decrypt_ecb(key16: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key16), modes.ECB())
    decryptor = cipher.decryptor()
    pt = decryptor.update(ciphertext) + decryptor.finalize()
    return pkcs7_unpad(pt)
