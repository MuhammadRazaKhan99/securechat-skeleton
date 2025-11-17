"""Append-only transcript + TranscriptHash helpers.""" 
raise NotImplementedError("students: implement transcript layer")
# app/storage/transcript.py
from pathlib import Path
import hashlib
import json
from typing import List
from app.crypto.sign import rsa_sign, load_private_key
from app.common.utils import b64

class Transcript:
    def __init__(self, filename: Path):
        self.filename = filename
        self.filename.parent.mkdir(parents=True, exist_ok=True)
        if not self.filename.exists():
            self.filename.write_text("")  # create

    def append(self, seqno: int, ts: int, ct_b64: str, sig_b64: str, peer_fingerprint: str):
        line = f"{seqno}|{ts}|{ct_b64}|{sig_b64}|{peer_fingerprint}\n"
        with open(self.filename, "a", newline="") as f:
            f.write(line)

    def lines(self) -> List[str]:
        with open(self.filename, "r") as f:
            return [l.strip() for l in f if l.strip()]

    def transcript_hash(self) -> str:
        lines = self.lines()
        cat = "".join(lines).encode()
        return hashlib.sha256(cat).hexdigest()

    def make_receipt(self, priv_key_pem: bytes, peer: str, first_seq: int, last_seq: int) -> dict:
        th = self.transcript_hash()
        priv = load_private_key(priv_key_pem)
        sig = rsa_sign(priv, th.encode())
        return {
            "type": "receipt",
            "peer": peer,
            "first_seq": first_seq,
            "last_seq": last_seq,
            "transcript_sha256": th,
            "sig": b64(sig)
        }
