"""Helper signatures: now_ms, b64e, b64d, sha256_hex."""

import base64
import hashlib
import time
import secrets
from typing import Union


def now_ms() -> int:
    """
    Get current Unix timestamp in milliseconds.
    
    Returns:
        Current timestamp as integer milliseconds
    """
    return int(time.time() * 1000)


def b64e(b: bytes) -> str:
    """
    Base64 encode bytes to string.
    
    Args:
        b: Bytes to encode
        
    Returns:
        Base64 encoded string
    """
    return base64.b64encode(b).decode('utf-8')


def b64d(s: str) -> bytes:
    """
    Base64 decode string to bytes.
    
    Args:
        s: Base64 encoded string
        
    Returns:
        Decoded bytes
        
    Raises:
        ValueError: If string is not valid base64
    """
    try:
        return base64.b64decode(s)
    except Exception as e:
        raise ValueError(f"Invalid base64 string: {e}")


def sha256_hex(data: bytes) -> str:
    """
    Compute SHA-256 hash and return as hex string.
    
    Args:
        data: Data to hash
        
    Returns:
        Hex string of SHA-256 hash
    """
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    """
    Compute SHA-256 hash and return as bytes.
    
    Args:
        data: Data to hash
        
    Returns:
        SHA-256 hash as bytes
    """
    return hashlib.sha256(data).digest()


def generate_nonce(length: int = 16) -> bytes:
    """
    Generate cryptographically secure random nonce.
    
    Args:
        length: Length of nonce in bytes (default: 16)
        
    Returns:
        Random bytes
    """
    return secrets.token_bytes(length)


def generate_salt(length: int = 16) -> bytes:
    """
    Generate cryptographically secure random salt for password hashing.
    
    Args:
        length: Length of salt in bytes (default: 16)
        
    Returns:
        Random salt bytes
    """
    return secrets.token_bytes(length)


def safe_compare(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
    """
    Constant-time string/bytes comparison to prevent timing attacks.
    
    Args:
        a: First value to compare
        b: Second value to compare
        
    Returns:
        True if values are equal
    """
    if isinstance(a, str):
        a = a.encode('utf-8')
    if isinstance(b, str):
        b = b.encode('utf-8')
    
    return secrets.compare_digest(a, b)


def bytes_to_int(data: bytes) -> int:
    """
    Convert bytes to integer (big-endian).
    
    Args:
        data: Bytes to convert
        
    Returns:
        Integer representation
    """
    return int.from_bytes(data, byteorder='big')


def int_to_bytes(value: int, length: int = None) -> bytes:
    """
    Convert integer to bytes (big-endian).
    
    Args:
        value: Integer to convert
        length: Fixed length in bytes (optional)
        
    Returns:
        Bytes representation
    """
    if length is None:
        # Calculate minimum bytes needed
        length = (value.bit_length() + 7) // 8
        if length == 0:
            length = 1
    
    return value.to_bytes(length, byteorder='big')


def truncate_bytes(data: bytes, length: int) -> bytes:
    """
    Truncate bytes to specified length.
    
    Args:
        data: Input bytes
        length: Desired length
        
    Returns:
        Truncated bytes
    """
    return data[:length]


def pad_message(message: str) -> str:
    """
    Add timestamp and formatting to console messages.
    
    Args:
        message: Message to format
        
    Returns:
        Formatted message with timestamp
    """
    timestamp = time.strftime("%H:%M:%S", time.localtime())
    return f"[{timestamp}] {message}"


def format_certificate_info(cert_info: dict) -> str:
    """
    Format certificate information for display.
    
    Args:
        cert_info: Certificate info dictionary
        
    Returns:
        Formatted string
    """
    return (
        f"Certificate Info:\n"
        f"  Common Name: {cert_info.get('common_name', 'N/A')}\n"
        f"  Serial: {cert_info.get('serial_number', 'N/A')}\n"
        f"  Valid: {cert_info.get('not_before', 'N/A')} to {cert_info.get('not_after', 'N/A')}\n"
        f"  Fingerprint: {cert_info.get('fingerprint', 'N/A')[:32]}..."
    )


def create_error_message(error_msg: str):
    """Create an ErrorMessage object."""
    from app.common.protocol import ErrorMessage
    
    # Parse error code from message
    if error_msg.startswith("BAD_CERT"):
        error_code = "BAD_CERT"
    elif error_msg.startswith("SIG_FAIL"):
        error_code = "SIG_FAIL"  
    elif error_msg.startswith("REPLAY"):
        error_code = "REPLAY"
    else:
        error_code = "ERROR"
    
    return ErrorMessage(error_code=error_code, message=error_msg)


def create_status_message(status: str, message: str):
    """Create a StatusMessage object."""
    from app.common.protocol import StatusMessage
    return StatusMessage(status=status, message=message)


def get_current_timestamp() -> int:
    """
    Get current timestamp in milliseconds since epoch.
    
    Returns:
        Current timestamp as integer
    """
    import time
    return int(time.time() * 1000)
