"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt."""

from pydantic import BaseModel, Field
from typing import Literal, Union, Optional
import json


# ==================== CONTROL PLANE MESSAGES ====================

class HelloMessage(BaseModel):
    """Client hello with certificate and nonce for freshness."""
    type: Literal["hello"] = "hello"
    client_cert: str = Field(..., description="PEM-encoded client certificate (base64)")
    nonce: str = Field(..., description="Base64-encoded random nonce for freshness")


class ServerHelloMessage(BaseModel):
    """Server hello response with certificate and nonce."""
    type: Literal["server_hello"] = "server_hello"
    server_cert: str = Field(..., description="PEM-encoded server certificate (base64)")
    nonce: str = Field(..., description="Base64-encoded random nonce for freshness")


class RegisterMessage(BaseModel):
    """User registration with encrypted credentials."""
    type: Literal["register"] = "register"
    email: str = Field(..., description="User email address")
    username: str = Field(..., description="Unique username")
    pwd: str = Field(..., description="Base64-encoded salted password hash: SHA256(salt||password)")
    salt: str = Field(..., description="Base64-encoded 16-byte random salt")


class SaltRequestMessage(BaseModel):
    """Request salt for login authentication."""
    type: Literal["salt_request"] = "salt_request"
    email: str = Field(..., description="User email address")
    nonce: str = Field(..., description="Base64-encoded random nonce for replay protection")


class SaltResponseMessage(BaseModel):
    """Salt response for login authentication."""
    type: Literal["salt_response"] = "salt_response"
    salt: str = Field(..., description="Base64-encoded salt for password hashing")
    exists: bool = Field(..., description="True if user exists, False otherwise")


class LoginMessage(BaseModel):
    """User login with encrypted credentials."""
    type: Literal["login"] = "login"
    email: str = Field(..., description="User email address")
    pwd: str = Field(..., description="Base64-encoded salted password hash: SHA256(salt||password)")
    nonce: str = Field(..., description="Base64-encoded random nonce for replay protection")


# ==================== KEY AGREEMENT MESSAGES ====================

class DHClientMessage(BaseModel):
    """Client DH key exchange with public parameters."""
    type: Literal["dh_client"] = "dh_client"
    g: int = Field(..., description="DH generator")
    p: int = Field(..., description="DH prime modulus")
    A: int = Field(..., description="Client's public DH value: g^a mod p")


class DHServerMessage(BaseModel):
    """Server DH key exchange response."""
    type: Literal["dh_server"] = "dh_server"
    B: int = Field(..., description="Server's public DH value: g^b mod p")


# ==================== DATA PLANE MESSAGES ====================

class ChatMessage(BaseModel):
    """Encrypted chat message with integrity protection."""
    type: Literal["msg"] = "msg"
    seqno: int = Field(..., description="Sequence number for replay protection")
    ts: int = Field(..., description="Unix timestamp in milliseconds")
    ct: str = Field(..., description="Base64-encoded AES-128 ciphertext (PKCS#7 padded)")
    sig: str = Field(..., description="Base64-encoded RSA signature over SHA256(seqno||ts||ct)")


# ==================== NON-REPUDIATION MESSAGES ====================

class SessionReceiptMessage(BaseModel):
    """Session transcript receipt for non-repudiation."""
    type: Literal["receipt"] = "receipt"
    peer: Literal["client", "server"] = Field(..., description="Who generated this receipt")
    first_seq: int = Field(..., description="First sequence number in session")
    last_seq: int = Field(..., description="Last sequence number in session")
    transcript_sha256: str = Field(..., description="Hex-encoded SHA-256 hash of transcript")
    sig: str = Field(..., description="Base64-encoded RSA signature over transcript hash")


# ==================== RESPONSE MESSAGES ====================

class StatusMessage(BaseModel):
    """Generic status/error response."""
    type: Literal["status"] = "status"
    status: str = Field(..., description="Status code: OK, ERROR, BAD_CERT, SIG_FAIL, REPLAY, etc.")
    message: str = Field(..., description="Human-readable status message")


class ErrorMessage(BaseModel):
    """Error response message.""" 
    type: Literal["error"] = "error"
    error_code: str = Field(..., description="Error code: BAD_CERT, SIG_FAIL, REPLAY, etc.")
    message: str = Field(..., description="Human-readable error message")


class AuthResultMessage(BaseModel):
    """Authentication result (login/register response)."""
    type: Literal["auth_result"] = "auth_result"
    success: bool = Field(..., description="True if authentication succeeded")
    message: str = Field(..., description="Success/error message")
    user_id: Optional[int] = Field(None, description="User ID if authentication succeeded")


# ==================== MESSAGE UNION TYPES ====================

# All possible message types for parsing
SecureChatMessage = Union[
    HelloMessage,
    ServerHelloMessage,
    RegisterMessage,
    SaltRequestMessage,
    SaltResponseMessage, 
    LoginMessage,
    DHClientMessage,
    DHServerMessage,
    ChatMessage,
    SessionReceiptMessage,
    StatusMessage,
    ErrorMessage,
    AuthResultMessage
]


# ==================== UTILITY FUNCTIONS ====================

def parse_message(json_data: str) -> SecureChatMessage:
    """
    Parse JSON string into appropriate message type based on 'type' field.
    
    Args:
        json_data: JSON string containing the message
        
    Returns:
        Parsed message object
        
    Raises:
        ValueError: If message type is unknown or invalid
        json.JSONDecodeError: If JSON is malformed
    """
    try:
        data = json.loads(json_data)
        msg_type = data.get("type")
        
        if msg_type == "hello":
            return HelloMessage(**data)
        elif msg_type == "server_hello":
            return ServerHelloMessage(**data)
        elif msg_type == "register":
            return RegisterMessage(**data)
        elif msg_type == "salt_request":
            return SaltRequestMessage(**data)
        elif msg_type == "salt_response":
            return SaltResponseMessage(**data)
        elif msg_type == "login":
            return LoginMessage(**data)
        elif msg_type == "dh_client":
            return DHClientMessage(**data)
        elif msg_type == "dh_server":
            return DHServerMessage(**data)
        elif msg_type == "msg":
            return ChatMessage(**data)
        elif msg_type == "receipt":
            return SessionReceiptMessage(**data)
        elif msg_type == "status":
            return StatusMessage(**data)
        elif msg_type == "auth_result":
            return AuthResultMessage(**data)
        else:
            raise ValueError(f"Unknown message type: {msg_type}")
            
    except Exception as e:
        raise ValueError(f"Failed to parse message: {e}")


def serialize_message(message: SecureChatMessage) -> str:
    """
    Serialize message object to JSON string.
    
    Args:
        message: Message object to serialize
        
    Returns:
        JSON string representation
    """
    return message.model_dump_json()


def create_status_message(status: str, message: str) -> StatusMessage:
    """Helper to create status messages."""
    return StatusMessage(status=status, message=message)


def create_error_message(error: str) -> StatusMessage:
    """Helper to create error messages."""
    return StatusMessage(status="ERROR", message=error)


# ==================== MESSAGE VALIDATION ====================

def validate_sequence_number(current_seq: int, expected_seq: int) -> bool:
    """
    Validate sequence number for replay protection.
    
    Args:
        current_seq: Sequence number from received message
        expected_seq: Expected next sequence number
        
    Returns:
        True if sequence number is valid
    """
    return current_seq == expected_seq


def validate_timestamp(ts: int, max_age_ms: int = 300000) -> bool:
    """
    Validate message timestamp for freshness (default: 5 minutes).
    
    Args:
        ts: Timestamp from message (Unix milliseconds)
        max_age_ms: Maximum age in milliseconds
        
    Returns:
        True if timestamp is fresh
    """
    import time
    current_time_ms = int(time.time() * 1000)
    age_ms = current_time_ms - ts
    
    return 0 <= age_ms <= max_age_ms
