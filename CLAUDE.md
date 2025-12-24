# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**CernCloud.Nas** is a secure Network-Attached Storage (NAS) system with **Zero-Knowledge encryption**. Files are encrypted client-side in the browser before upload, ensuring the server never has access to encryption keys or plaintext data. The system supports multi-device authorization with 6-digit codes and flexible security levels.

## Architecture

### Multi-Container Docker Setup

The system runs three containers orchestrated by Docker Compose:

1. **ldap** (OpenLDAP): User directory and authentication
2. **server** (Storage Server): TCP socket server on port 65432 for file storage
3. **client** (Flask Web Client): Web UI on port 5000

### Key Components

**Backend (Python 3.11)**
- `web_client/app.py`: Flask application (~2867 lines) - main entry point for web UI
- `storage_server/server.py`: TCP socket server handling file operations (upload, download, versioning)
- `lib/`: Shared library modules

**Frontend (Browser)**
- Client-side encryption using Web Crypto API
- JavaScript modules: `crypto_client.js`, `device_crypto.js`, `device_fingerprint.js`

**Infrastructure**
- LDAP authentication with optional fallback to LDIF import
- SQLite for metadata (activity logs, device registry)
- File storage with automatic versioning in `.versions/` subdirectories

### Crypto Architecture

**Two Security Levels:**

1. **Standard Mode**: EC P-256 (ECDH) + AES-256-GCM
2. **Maximum Mode**: X25519 (Curve25519-ECDH) + AES-256-GCM

**Encryption Flow:**
1. User generates asymmetric keypair (X25519 or EC P-256) in browser
2. Private key encrypted with user password using PBKDF2 (100k iterations)
3. Public key sent to server, private key stored encrypted on server
4. For file upload:
   - Generate random AES-256 key
   - Encrypt file with AES-GCM → `file.enc`
   - Encrypt AES key with recipient's public key (ECDH) → `file.key`
   - Upload both files
5. For file download:
   - Download `file.enc` + `file.key`
   - Decrypt AES key using private key (ECDH)
   - Decrypt file with AES key

**Key Modules:**
- `lib/crypto/client_crypto.py`: X25519/EC encryption (backend)
- `lib/crypto/crypto_utils.py`: Legacy crypto utilities
- `lib/crypto/device_keys.py`: Device key management
- `web_client/static/js/crypto_client.js`: Browser-side encryption

### Authentication & Device Management

**LDAP Integration:**
- Direct bind authentication (no group lookups)
- Configurable via environment variables
- Users imported from `ldap_bootstrap/01-users.ldif`

**Multi-Device Authorization:**
- `lib/auth/device_manager.py`: Device registry and authorization
- `lib/auth/qr_authorization.py`: Temporary 6-digit codes (60s expiry)
- First device = master device (trust anchor)
- Additional devices authorized via 6-digit code + cryptographic signatures (Ed25519)
- Device fingerprinting for unique identification

**Security Manager:**
- `lib/auth/security_manager.py`: Manages per-user security levels
- Tracks device registry and key migration status

### File Operations (TCP Protocol)

The storage server uses a custom binary protocol:

**Message Types:**
- `F`: Upload file
- `K`: Upload public key
- `P`: Download public key
- `L`: List files
- `G`: Download file
- `V`: List versions
- `R`: Restore version
- `D`: Delete file
- `M`: Delete folder
- `X`: Delete version (admin only)
- `E`: End connection

**Format:** `[1 byte command][4 bytes username length][username][payload]`

### Monitoring & Logging

- `lib/monitoring/activity_logger.py`: Audit trail for all user actions
- `lib/monitoring/admin_security.py`: Admin-specific security monitoring
- Logs stored in SQLite database

## Development Commands

### Build and Run

```bash
# Generate Flask secret key (first time only)
python3 scripts/generate_secret.py
# Copy output to .env as SECRET_KEY

# Build and start all services
docker-compose up --build -d

# View logs
docker-compose logs -f client
docker-compose logs -f server
docker-compose logs -f ldap

# Stop services
docker-compose down

# Full cleanup (removes volumes)
docker-compose down -v
```

### Testing

```bash
# Run crypto tests
docker exec -it nas_client python3 /app/lib/crypto/client_crypto.py

# Run device manager tests
docker exec -it nas_client python3 /app/lib/auth/device_manager.py

# Test LDAP connection
docker exec -it nas_ldap ldapsearch -x -H ldap://localhost -b "dc=nas,dc=local" -D "cn=admin,dc=nas,dc=local" -w ${LDAP_ADMIN_PASSWORD}
```

### Development Workflow

```bash
# Restart client after code changes
docker-compose restart client

# Restart storage server
docker-compose restart server

# Rebuild containers after dependency changes
docker-compose up --build -d

# Access container shell
docker exec -it nas_client /bin/bash
docker exec -it nas_server /bin/bash
```

## Configuration

### Environment Variables (.env)

**Flask:**
- `SECRET_KEY`: Flask session secret (generate with `scripts/generate_secret.py`)
- `FLASK_PORT`: Web UI port (default: 5000)
- `ADMIN_USERNAME`: Admin username (default: admin)

**LDAP:**
- `LDAP_ORGANISATION`: Organization name
- `LDAP_DOMAIN`: LDAP domain (e.g., nas.local)
- `LDAP_BASE_DN`: Base DN (e.g., dc=nas,dc=local)
- `LDAP_ADMIN_PASSWORD`: LDAP admin password
- `FLASK_LDAP_HOST`: LDAP server (e.g., ldap://ldap:389)

**Storage:**
- `STORAGE_SERVER_IP`: Storage server hostname (default: server)
- `STORAGE_SERVER_PORT`: Storage server port (default: 65432)

### Directory Structure

```
nas/
├── web_client/           # Flask application
│   ├── app.py           # Main Flask app (~2867 lines)
│   ├── static/js/       # Client-side crypto
│   └── templates/       # HTML templates
├── storage_server/       # TCP storage server
│   └── server.py        # File operations handler
├── lib/                 # Shared libraries
│   ├── auth/           # Authentication & devices
│   ├── crypto/         # Encryption modules
│   └── monitoring/     # Logging & audit
├── ldap_bootstrap/      # LDAP initial users
├── scripts/            # Utility scripts
├── user_keys/          # User public keys (volume)
├── storage/            # Encrypted files (volume)
├── data/               # SQLite databases (volume)
└── docker-compose.yml  # Service orchestration
```

## Important Implementation Details

### Zero-Knowledge Guarantees

- Server stores **only**: encrypted private keys, public keys, encrypted files, metadata
- Server **never** sees: passwords, plaintext private keys, plaintext files
- Password loss = permanent data loss (no recovery mechanism)

### File Versioning

- Automatic versioning on file overwrite
- Versions stored in `.versions/<filename>/<timestamp>.enc`
- Both `.enc` and `.key` files are versioned together
- Admin can delete old versions to save space

### Security Considerations

**What's Protected:**
- File contents (encrypted client-side)
- Private keys (encrypted with user password)
- Device authorization (cryptographic signatures)

**What's NOT Protected:**
- Filenames (visible to server)
- File sizes (visible to server)
- Timestamps (visible to server)
- Directory structure (visible to server)

**Path Traversal Protection:**
- All file paths validated with `safe_join()` in `storage_server/server.py:84`
- Prevents `../` attacks

### Browser Compatibility

- Requires Web Crypto API support
- X25519 not universally supported → falls back to EC P-256
- Both modes accepted by backend (`lib/crypto/client_crypto.py:106-122`)

## Common Tasks

### Adding a New Route

1. Add route handler in `web_client/app.py`
2. Use `@login_required` decorator for protected routes
3. Log activity with `activity_logger.log_action(username, action, details)`
4. Add HTML template in `web_client/templates/`

### Modifying Crypto

1. **Backend**: Edit `lib/crypto/client_crypto.py` or `crypto_utils.py`
2. **Frontend**: Edit `web_client/static/js/crypto_client.js`
3. Ensure compatibility between browser (EC P-256) and backend (X25519/EC)
4. Test with both security levels

### Adding Storage Server Command

1. Add message type constant (e.g., `b'N'`) in `storage_server/server.py:39-76`
2. Implement handler function (e.g., `handle_new_operation`)
3. Add case to main message loop in `handle_client()`
4. Update client in `web_client/app.py` to send new message type

### LDAP User Management

Users imported from `ldap_bootstrap/01-users.ldif` on first startup:
- Edit LDIF file to add/modify users
- Restart containers: `docker-compose down && docker-compose up -d`
- New users only added if LDAP is empty

## Debugging

### Common Issues

**"Code invalide" during device authorization:**
- Codes expire after 60 seconds
- Check clock sync between devices
- Check `lib/auth/qr_authorization.py` session management

**Files won't decrypt:**
- Verify correct password
- Check security level matches key type
- Inspect browser console for Web Crypto API errors

**LDAP authentication fails:**
- Verify LDAP container health: `docker-compose ps`
- Test bind: `docker exec nas_ldap ldapsearch ...`
- Check `.env` LDAP credentials

**Storage server connection refused:**
- Check server container: `docker-compose logs server`
- Verify `STORAGE_SERVER_IP` and `STORAGE_SERVER_PORT`
- Check healthcheck: `docker inspect nas_server`

### Logs

```bash
# Application logs
docker-compose logs -f client

# Storage server logs
docker-compose logs -f server

# LDAP logs
docker-compose logs -f ldap

# All services
docker-compose logs -f
```

## Testing Approach

Since this is a security-focused application:

1. **Manual testing** is primary (UI flows, encryption/decryption)
2. **Module tests** embedded in Python files (run with `if __name__ == "__main__"`)
3. Test both security levels when modifying crypto
4. Test multi-device flows with multiple browsers/devices
5. Verify audit logs after operations