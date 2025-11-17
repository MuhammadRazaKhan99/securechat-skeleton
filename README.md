
# CS3002 Assignment A1 - SecureChat Protocol

**Student:** Raza Khan  
**Assignment:** A1 - Secure Chat Application  
**Course:** CS3002 - Computer Security  
**Date:** November 2025

## Overview

This is a secure chat application implementing a 4-phase protocol with end-to-end encryption, digital signatures, and PKI-based authentication. The system provides all CIANR security properties: Confidentiality, Integrity, Authentication, Non-repudiation, and Replay protection.

## Implementation Status

All required features have been implemented and tested:
- 4-phase secure communication protocol
- PKI infrastructure with certificate validation
- AES-128 encryption with proper key management
- RSA digital signatures for message integrity
- Replay protection with sequence numbers
- Non-repudiation with session transcripts
- Comprehensive security testing

## System Requirements

- Python 3.8+
- MySQL Server
- Required Python packages (see requirements.txt)

## File Structure

```
securechat-skeleton/
├── app/
│   ├── client.py           # Chat client application
│   ├── server.py           # Chat server application
│   ├── common/
│   │   ├── protocol.py     # Message definitions
│   │   └── utils.py        # Utility functions
│   ├── crypto/
│   │   ├── aes.py          # AES encryption
│   │   ├── dh.py           # Diffie-Hellman key exchange
│   │   ├── pki.py          # Certificate validation
│   │   └── sign.py         # Digital signatures
│   └── storage/
│       ├── db.py           # Database operations
│       └── transcript.py   # Session logging
├── certs/                  # PKI certificates
├── scripts/
│   ├── gen_ca.py          # CA generation
│   └── gen_cert.py        # Certificate generation
├── tests/                  # Security tests
├── transcripts/           # Session transcripts
├── receipts/              # Session receipts
└── requirements.txt       # Python dependencies
```

## Setup Instructions

### 1. Database Setup
```bash
# Create MySQL database
mysql -u root -p
CREATE DATABASE securechat;
CREATE USER 'securechat'@'localhost' IDENTIFIED BY 'password123';
GRANT ALL PRIVILEGES ON securechat.* TO 'securechat'@'localhost';
exit

# Or run the setup script
./setup_database.sh
```

### 2. Environment Configuration
```bash
# Copy environment file
cp .env.example .env

# Edit .env with your database credentials
DB_HOST=localhost
DB_PORT=3306
DB_NAME=securechat
DB_USER=securechat
DB_PASSWORD=password123
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Generate Certificates
```bash
# Generate CA and certificates
python scripts/gen_ca.py
python scripts/gen_cert.py
```

## Running the Application

### Start the Server
```bash
cd securechat-skeleton
PYTHONPATH=/path/to/securechat-skeleton python -m app.server
```

### Start the Client
```bash
cd securechat-skeleton  
PYTHONPATH=/path/to/securechat-skeleton python -m app.client
```

### Register a New User
1. Run the client
2. Choose option 1 (Register)
3. Enter email, username, and password
4. Registration will be confirmed

### Login and Chat
1. Run the client
2. Choose option 2 (Login)
3. Enter registered email and password
4. Start chatting
5. Type `/quit` to exit

## Security Features Implemented

### 1. PKI Infrastructure
- Root CA certificate generation
- X.509 certificate issuance for clients and server
- Certificate validation and trust chain verification

### 2. 4-Phase Protocol
- **Phase 1:** Control Plane - Certificate exchange and authentication
- **Phase 2:** Key Agreement - Diffie-Hellman key exchange
- **Phase 3:** Data Plane - Encrypted message exchange
- **Phase 4:** Teardown - Session cleanup and receipt generation

### 3. Cryptographic Features
- **Encryption:** AES-128 with PKCS#7 padding
- **Signatures:** RSA-2048 digital signatures over SHA-256 hashes
- **Key Derivation:** SHA-256 based key derivation from DH shared secret
- **Authentication:** Salt-based password hashing with SHA-256

### 4. Security Properties (CIANR)
- **Confidentiality:** All messages encrypted with AES-128
- **Integrity:** RSA signatures detect message tampering
- **Authentication:** PKI certificates verify identities
- **Non-repudiation:** Session transcripts with cryptographic evidence
- **Replay Protection:** Sequence numbers prevent message replay

## Testing

### Security Tests
```bash
# Certificate validation testing
python tests/test_invalid_cert.py

# Message tampering detection
python tests/test_tampering_verification.py

# Replay attack protection  
python tests/test_replay_verification.py

# Non-repudiation evidence
python tests/test_nonrepudiation_simple.py
```

### Network Analysis
Use Wireshark to capture traffic on port 8443:
```
tcp.port == 8443
```
All message content should appear as encrypted Base64 data.

## Database Schema

```sql
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(255) UNIQUE NOT NULL,
    salt VARCHAR(255) NOT NULL,
    pwd_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Protocol Messages

- `hello` - Client certificate and nonce
- `server_hello` - Server certificate response
- `salt_request` - Request salt for authentication
- `salt_response` - Salt for password hashing
- `login` - Authentication with salted password hash
- `dh_client` - Diffie-Hellman parameters from client
- `dh_server` - Diffie-Hellman response from server
- `msg` - Encrypted chat message with signature
- `receipt` - Session transcript receipt

## Error Handling

The system handles various security errors:
- `BAD_CERT` - Invalid or untrusted certificates
- `SIG_FAIL` - Message signature verification failure
- `REPLAY` - Invalid sequence number (replay attack)
- `ERROR` - General protocol or system errors

## Test Evidence Completed

- [x] Wireshark capture showing encrypted payloads only
- [x] Invalid certificate rejection with BAD_CERT errors
- [x] Message tampering detection with SIG_FAIL responses
- [x] Replay attack protection with REPLAY errors
- [x] Non-repudiation evidence with transcript verification

## Troubleshooting

### Common Issues

1. **Certificate errors:** Regenerate certificates with scripts/gen_cert.py
2. **Database connection:** Check .env configuration and MySQL service
3. **Import errors:** Ensure PYTHONPATH is set correctly
4. **Permission errors:** Check file permissions on certificate files

## Assignment Deliverables

- [x] Complete 4-phase protocol implementation
- [x] PKI infrastructure with certificate validation
- [x] AES-128 encryption with proper key management
- [x] RSA digital signatures for message integrity
- [x] Replay protection with sequence numbers
- [x] Non-repudiation with session transcripts
- [x] Security testing and validation
- [x] Network traffic analysis with Wireshark
- [x] Documentation and README

## Notes

This implementation demonstrates all required security properties for the CS3002 assignment. The system provides secure communication with proper cryptographic foundations and comprehensive security testing.  
