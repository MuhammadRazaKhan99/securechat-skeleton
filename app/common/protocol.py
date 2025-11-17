"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt.""" 
raise NotImplementedError("students: define pydantic models")
# app/common/protocol.py
from pydantic import BaseModel
from typing import Optional

class Hello(BaseModel):
    type: str = "hello"
    cert: str  # PEM string (base64 or raw PEM)
    nonce: str

class ServerHello(BaseModel):
    type: str = "server hello"
    cert: str
    nonce: str

class Register(BaseModel):
    type: str = "register"
    email: str
    username: str
    pwd: str  # base64(sha256(salt||pwd))
    salt: str

class Login(BaseModel):
    type: str = "login"
    email: str
    pwd: str
    nonce: str

class DHClient(BaseModel):
    type: str = "dh client"
    g: int
    p: int
    A: int

class DHServer(BaseModel):
    type: str = "dh server"
    B: int

class Msg(BaseModel):
    type: str = "msg"
    seqno: int
    ts: int
    ct: str
    sig: str

class Receipt(BaseModel):
    type: str = "receipt"
    peer: str
    first_seq: int
    last_seq: int
    transcript_sha256: str
    sig: str
