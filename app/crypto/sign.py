"""RSA PKCS#1 v1.5 SHA-256 sign/verify.""" 
raise NotImplementedError("students: implement RSA helpers")
# app/crypto/sign.py
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

def load_private_key(pem_bytes: bytes):
    return serialization.load_pem_private_key(pem_bytes, password=None)

def load_public_key_from_cert(cert):
    return cert.public_key()

def rsa_sign(priv_key: RSAPrivateKey, data: bytes) -> bytes:
    return priv_key.sign(data, padding.PKCS1v15(), hashes.SHA256())

def rsa_verify(pub_key, sig: bytes, data: bytes) -> bool:
    try:
        pub_key.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False
