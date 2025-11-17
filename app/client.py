# app/client.py
import socket, json, os
from pathlib import Path
from app.common.utils import b64, ub64, now_ms, random_bytes, sha256_hex
from app.crypto.dh import compute_public, compute_shared, derive_aes_key_from_shared
from app.crypto.aes import aes_encrypt_ecb, aes_decrypt_ecb
from app.crypto.sign import load_private_key, rsa_sign
from cryptography import x509
import random, base64, hashlib

CERT_DIR = Path("certs")
CLIENT_CERT = CERT_DIR / "client.cert.pem"
CLIENT_KEY = CERT_DIR / "client.key.pem"
CA_CERT = CERT_DIR / "ca_cert.pem"

HOST = "127.0.0.1"
PORT = 9009

def recvall(sock):
    data = sock.recv(4)
    if not data:
        return None
    n = int.from_bytes(data, "big")
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf

def sendmsg(sock, obj):
    b = json.dumps(obj).encode()
    sock.sendall(len(b).to_bytes(4,"big") + b)

def main():
    client_cert_pem = CLIENT_CERT.read_text()
    sock = socket.socket()
    sock.connect((HOST, PORT))
    # send hello
    sendmsg(sock, {"type":"hello", "cert": client_cert_pem, "nonce": os.urandom(12).hex()})
    # recv server hello
    data = recvall(sock)
    sh = json.loads(data.decode())
    server_cert_pem = sh["cert"]
    # initial DH (temporary) for registration/login
    # use small safe primes? For demo use 2048-bit DH params or simple numbers
    p = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" + "..." , 16) if False else 0
    # For simplicity use a small built-in prime (not secure in prod). Assignment expects classical DH; replace with standard params.
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1FFFFFFFFFFFFFFFF
    g = 2
    a = random.getrandbits(256)
    A = pow(g, a, p)
    sendmsg(sock, {"type":"dh client", "g": g, "p": p, "A": A})
    data = recvall(sock)
    dhs = json.loads(data.decode()); B = int(dhs["B"])
    shared = pow(B, a, p)
    aes_key = derive_aes_key_from_shared(shared)
    # Register: build payload and encrypt under ephemeral AES
    salt = os.urandom(16)
    pwd_plain = "password123"  # in real use read from user
    # client sends base64(sha256(salt||pwd)) as per spec
    h = hashlib.sha256(salt + pwd_plain.encode()).hexdigest()
    payload = {"type":"register", "email":"student@fast.edu", "username":"student", "pwd": h, "salt": base64.b64encode(salt).decode()}
    pt = json.dumps(payload).encode()
    ct = aes_encrypt_ecb(aes_key, pt)
    sendmsg(sock, {"ct": b64(ct)})
    resp = json.loads(recvall(sock).decode())
    print("reg response:", resp)
    # After register/login, new session DH handshake
    a2 = random.getrandbits(256)
    A2 = pow(g, a2, p)
    sendmsg(sock, {"type":"dh client", "g": g, "p": p, "A": A2})
    data = recvall(sock)
    dhs2 = json.loads(data.decode()); B2 = int(dhs2["B"])
    shared2 = pow(B2, a2, p)
    session_key = derive_aes_key_from_shared(shared2)
    # Now send a message: encrypt using session_key, sign SHA256(seq||ts||ct)
    priv = load_private_key(CLIENT_KEY.read_bytes())
    seqno = 1
    while True:
        msg = input("Message (or .exit): ")
        if msg.strip() == ".exit":
            break
        ct = aes_encrypt_ecb(session_key, msg.encode())
        ct_b64 = b64(ct)
        ts = now_ms()
        h = hashlib.sha256(f"{seqno}{ts}{ct_b64}".encode()).digest()
        sig = rsa_sign(priv, h)
        sendmsg(sock, {"type":"msg", "seqno": seqno, "ts": ts, "ct": ct_b64, "sig": b64(sig)})
        resp = json.loads(recvall(sock).decode())
        print("server:", resp)
        seqno += 1
    # After finishing, expect to receive server receipt
    data = recvall(sock)
    if data:
        rec = json.loads(data.decode())
        print("Server receipt:", rec)

if __name__ == "__main__":
    main()
