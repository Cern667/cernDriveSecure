# CernCloud.Nas - Zero-Knowledge Network Attached Storage

A secure, zero-knowledge encrypted NAS system with client-side encryption. Files are encrypted in the browser before upload, ensuring the server never has access to encryption keys or plaintext data.

[Français](README.fr.md)

---

## Key Features

- **Zero-Knowledge Architecture**: Server never sees unencrypted data or keys
- **Client-Side Encryption**: AES-256-GCM + X25519/EC P-256 ECDH
- **Multi-Device Support**: Authorize new devices with cryptographic signatures
- **File Versioning**: Automatic version history with rollback capability
- **Two Security Modes**:
  - Standard: EC P-256 with server-side decryption
  - Maximum: X25519 with client-side only decryption
- **LDAP Authentication**: Enterprise-ready user directory
- **Activity Logging**: Comprehensive audit trails

---

## Quick Start

### Prerequisites
- Docker & Docker Compose
- 2GB RAM minimum
- Linux/macOS/Windows (WSL2)

### Installation

**Option 1: Docker Compose (Recommended)**

```bash
git clone https://github.com/Nolan667/cernDriveSecure.git
cd nas
cp .env.example .env
nano .env  # Edit SECRET_KEY and passwords
docker-compose up -d
```

Access: `http://localhost:5000`

**Option 2: Automated Script**

```bash
./start.sh  # Creates .env, generates SECRET_KEY, starts containers
```

### Configuration

Edit `.env` before starting:

```bash
# Required - Generate with: python3 scripts/generate_secret.py
SECRET_KEY=your-generated-secret-key

# Admin credentials (CHANGE THESE)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin

# LDAP configuration
LDAP_ORGANISATION=Your Company
LDAP_DOMAIN=nas.local
LDAP_BASE_DN=dc=nas,dc=local
LDAP_ADMIN_PASSWORD=admin

# Application
FLASK_PORT=5000
```

**Security Note**: Never commit `.env` to version control. It's excluded via `.gitignore`.

### Cleanup

```bash
./scripts/cleanup.sh stop   # Stop containers (keeps data)
./scripts/cleanup.sh clean  # Remove containers + volumes
./scripts/cleanup.sh purge  # Full cleanup including images
```

---

## Architecture

### Stack
- **Frontend**: Vanilla JS with Web Crypto API
- **Backend**: Python 3.11 + Flask
- **Storage**: TCP socket server (port 65432)
- **Authentication**: OpenLDAP
- **Encryption**: X25519/EC P-256 + AES-256-GCM

### Components

**Docker Services**:
- `ldap`: OpenLDAP user directory (port 389)
- `server`: Storage server for encrypted files
- `client`: Flask web interface (port 5000)

**Key Modules**:
- `lib/auth/`: Device manager, security levels, QR authorization
- `lib/crypto/`: X25519/EC encryption, key management
- `lib/monitoring/`: Activity logging, admin security
- `web_client/`: Flask app, templates, client-side crypto

### Encryption Flow

**Standard Mode (EC P-256)**:
1. User generates EC P-256 keypair in browser
2. Private key encrypted with password (PBKDF2, 100k iterations)
3. Encrypted private key stored on server
4. Files encrypted with random AES-256 key
5. AES key encrypted with recipient's public key (ECDH)
6. Server decrypts files using stored private key

**Maximum Mode (X25519)**:
1. Same keypair generation but with X25519
2. Private key NEVER sent to server
3. All decryption happens client-side in browser
4. Password required for each decryption session

### Zero-Knowledge Guarantees

**Server Stores**:
- Encrypted private keys (password-protected)
- Public keys
- Encrypted files (.enc)
- Encrypted AES keys (.key)
- Metadata (filenames, timestamps)

**Server NEVER Sees**:
- Passwords
- Plaintext private keys
- Plaintext files
- Plaintext AES keys

**WARNING**: Password loss = permanent data loss. No recovery possible.

---

## Usage

### Initial Setup (First Device)

1. Login at `http://localhost:5000`
2. Click "Generate my encryption keys"
3. Choose security level (Standard or Maximum)
4. Create a strong master password
5. Save password securely - cannot be recovered

### Adding a New Device

**On new device**:
1. Login with credentials
2. A 6-digit authorization code appears (valid 60 seconds)

**On trusted device**:
1. Go to "Device Connection"
2. Enter the 6-digit code
3. Approve authorization

**Back on new device**:
1. Enter master password
2. Device is now authorized

### File Operations

**Upload**:
1. Go to "My Files"
2. Drag & drop or select files
3. Files encrypted automatically before upload

**Download**:
- **Standard mode**: Click download (decrypts on server)
- **Maximum mode**: Enter password (decrypts in browser)

**Versioning**:
- Files are automatically versioned on overwrite
- View versions in "Versions" tab
- Download or restore previous versions

---

## Security

### Best Practices

1. **Use strong passwords**: Master password encrypts your private key
2. **Enable Maximum mode**: For highest security (client-side only)
3. **Backup passwords**: Store in a password manager
4. **Change default credentials**: Update `ADMIN_PASSWORD` and `LDAP_ADMIN_PASSWORD`
5. **Generate strong SECRET_KEY**: Use `scripts/generate_secret.py`
6. **Revoke compromised devices**: From "Device Connection" interface

### Threat Model

**Protected Against**:
- Server compromise (encrypted data)
- Network interception (TLS recommended)
- Database leaks (keys are encrypted)
- Unauthorized device access (cryptographic authorization)

**Not Protected Against**:
- Client-side malware (can steal password during entry)
- Physical access to unlocked device
- Password compromise (enables decryption)
- Browser vulnerabilities

### Production Deployment

1. Use HTTPS/TLS for all connections
2. Change all default passwords in `.env`
3. Generate unique `SECRET_KEY` per deployment
4. Use strong `LDAP_ADMIN_PASSWORD`
5. Implement network isolation (firewall rules)
6. Regular backups of encrypted data
7. Monitor activity logs for suspicious behavior

---

## Development

### File Structure

```
nas/
├── docker-compose.yml      # Service orchestration
├── Dockerfile              # Multi-stage build
├── .env.example            # Configuration template
├── start.sh                # Automated deployment
├── scripts/
│   └── cleanup.sh          # Cleanup utility
├── lib/
│   ├── auth/               # Authentication & devices
│   ├── crypto/             # Encryption modules
│   └── monitoring/         # Logging
├── web_client/
│   ├── app.py              # Flask application
│   ├── static/js/          # Client-side crypto
│   └── templates/          # HTML templates
├── storage_server/
│   └── server.py           # TCP storage server
└── ldap_bootstrap/
    └── 01-users.ldif       # Initial LDAP users
```

### Commands

```bash
# View logs
docker-compose logs -f
docker-compose logs -f client
docker-compose logs -f server

# Restart service
docker-compose restart client

# Rebuild after code changes
docker-compose up --build -d

# Access container shell
docker exec -it nas_client /bin/bash
```

### Adding Users

Edit `ldap_bootstrap/01-users.ldif` and restart:

```bash
docker-compose down
docker-compose up -d
```

---

## Troubleshooting

**"Invalid code" during device authorization**:
- Codes expire after 60 seconds
- Check system clock sync
- Regenerate code if expired

**Files won't decrypt**:
- Verify correct password
- Check security level matches key type
- Check browser console for errors

**LDAP authentication fails**:
- Verify LDAP container: `docker-compose ps`
- Check credentials in `.env`
- Test LDAP bind: `docker exec nas_ldap ldapsearch -x -H ldap://localhost`

**Storage server connection refused**:
- Check server logs: `docker-compose logs server`
- Verify `STORAGE_SERVER_IP` and `STORAGE_SERVER_PORT` in `.env`

---

## License

[Your License Here]

## Contributing

[Your Contributing Guidelines Here]
