# 🛡️ CernCloud.Nas - Secure NAS with Zero-Knowledge Encryption

**CernCloud.Nas** is a secure Network-Attached Storage (NAS) solution featuring **Zero-Knowledge encryption**, ensuring that your files are protected with end-to-end encryption where the server never has access to your encryption keys or data.

[🇫🇷 French version](README.fr.md)

---

## ✨ Key Features

### 🔐 **Zero-Knowledge Architecture**
- **Client-side encryption**: All encryption/decryption happens in your browser
- **Password-based key derivation**: Your private key is encrypted with YOUR password using PBKDF2
- **Server-blind**: The server never knows your password or private key
- **Multi-device support** with 6-digit authorization codes

### 🔒 **Security**
- **X25519** (Curve25519) for ECDH key exchange
- **AES-256-GCM** for file encryption
- **Ed25519** for device signature verification
- **PBKDF2** (100,000 iterations) for password-based key encryption
- **Device fingerprinting** for unique device identification
- **LDAP authentication** for enterprise user management

### 📁 **File Management**
- **Upload/Download**: Drag-and-drop interface for encrypted file uploads
- **Versioning**: Automatic file versioning with restore capabilities
- **Folder support**: Organize files in encrypted folders
- **Search**: Full-text search across encrypted files
- **Quotas**: Per-user storage limits

### 👥 **Multi-Device Management**
- **Device authorization**: Add new devices with simple 6-digit codes
- **Device revocation**: Remove devices instantly
- **Device tracking**: Monitor all connected devices with detailed information
- **Master device**: First device acts as the trust anchor

### 📊 **Administration**
- **User management**: LDAP-based user administration
- **Activity logs**: Comprehensive audit trails
- **Security levels**: Flexible security modes per user
- **Global security mode**: System-wide security policy enforcement

---

## 🚀 Quick Start

### **Prerequisites**
- Docker & Docker Compose
- 2GB RAM minimum
- Linux/macOS/Windows (WSL2)

### **Installation**

#### **Option 1: Automated Setup (Recommended)**

The easiest way to get started is using the provided startup script:

```bash
# Clone the repository
git clone <repository-url>
cd nas

# Launch the automated setup
./start.sh
```

The script will automatically:
- Create `.env` from `.env.example` if needed
- Generate a secure Flask `SECRET_KEY`
- Build and start all Docker containers
- Display the application URL and default credentials

**Quick start without confirmation:**
```bash
./start.sh -y
```

#### **Option 2: Manual Setup**

1. **Clone the repository**
```bash
git clone <repository-url>
cd nas
```

2. **Configure environment**
```bash
cp .env.example .env
nano .env  # Edit with your values
```

3. **Generate Flask secret key**
```bash
python3 scripts/generate_secret.py
# Copy the generated key to .env
```

4. **Start the services**
```bash
docker-compose up --build -d
```

5. **Access the application**
```
http://localhost:5000
```

### **Stopping and Cleanup**

Use the cleanup script for different levels of cleanup:

```bash
# Stop containers (keeps data)
./scripts/cleanup.sh stop

# Remove containers and volumes (deletes LDAP data)
./scripts/cleanup.sh clean

# Full cleanup (containers + volumes + Docker images)
./scripts/cleanup.sh purge
```

**Interactive mode** (with menu):
```bash
./scripts/cleanup.sh
```

---

## 📋 Configuration

### **Environment Variables (.env)**

```bash
# Flask
SECRET_KEY=<generate-with-generate_secret.py>
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin

# LDAP
LDAP_ORGANISATION=NAS Company
LDAP_DOMAIN=nas.local
LDAP_BASE_DN=dc=nas,dc=local
LDAP_ADMIN_PASSWORD=admin

# Application
FLASK_PORT=5000
```

### **First Login**

1. Navigate to `http://localhost:5000`
2. Login with default admin credentials (configured in `.env`)
3. You'll be prompted to generate encryption keys
4. **IMPORTANT**: Remember your master password – it CANNOT be recovered!

---

## 💡 Usage

### **Initial Setup (First Device)**

1. Login to your account
2. Create a **strong master password** (encrypts your private key)
3. Click "Generate my encryption keys"
4. Save your password securely – **loss means permanent data loss**

### **Adding a New Device**

**On the new device:**
1. Login with your credentials
2. A **6-digit code** will be displayed (valid for 60 seconds)

**On a trusted device:**
1. Click "Connexion appareil" in the sidebar
2. Enter the 6-digit code shown on the new device
3. Click "Autoriser l'appareil"

**Back on the new device:**
1. Enter your **master password**
2. Device is now authorized and can decrypt your files

### **Uploading Files**

1. Go to "Mes Fichiers"
2. Drag & drop files or click to browse
3. Files are **automatically encrypted** before upload
4. Server stores only encrypted data

### **Downloading Files**

1. Browse to your file
2. Click "Download"
3. File is **decrypted in your browser**
4. Save the decrypted file locally

### **Managing Devices**

1. Go to "Connexion appareil" (sidebar)
2. View all connected devices
3. Authorize new devices with 6-digit codes
4. Revoke access from compromised devices

---

## 🔧 Tech Stack

### **Backend**
- **Flask**: Web framework
- **Python 3.11**: Core language
- **LDAP**: User authentication
- **SQLite**: Metadata storage (logs, activity)

### **Frontend**
- **HTML5 + CSS3**: Modern UI
- **JavaScript (ES6+)**: Client-side logic
- **Web Crypto API**: Browser-based encryption
- **Lucide Icons**: Modern iconography

### **Encryption**
- **X25519** (Curve25519-ECDH): Key exchange
- **Ed25519**: Digital signatures (device auth)
- **AES-256-GCM**: Symmetric encryption
- **PBKDF2**: Password-based key derivation

### **Infrastructure**
- **Docker**: Containerization
- **Docker Compose**: Multi-container orchestration
- **OpenLDAP**: Directory services

---

## 🛡️ Security Considerations

### **✅ What is protected**
- All files are encrypted client-side before upload
- Private keys are encrypted with user passwords
- Server cannot decrypt any user data
- Device authorization uses cryptographic signatures

### **⚠️ Limitations**
- **Password loss = data loss**: There is NO password recovery
- **Metadata is visible**: File names, sizes, and timestamps are stored unencrypted
- **Browser security**: Client-side crypto relies on browser security

### **🔑 Best Practices**
1. Use a **strong, unique master password** (20+ characters)
2. Store password in a **password manager**
3. Regularly **review authorized devices**
4. **Revoke devices** when no longer needed
5. Keep **backups** of critical encrypted files

---

## 📜 License

© 2025 CernCloud Systems. All rights reserved.

---

## 🆘 Support

### **Common Issues**

**Problem**: "Code invalide" when authorizing device  
**Solution**: Codes expire after 60 seconds. Generate a new code.

**Problem**: "Clé privée chiffrée introuvable"  
**Solution**: Run the initial setup on `/setup-keys` first.

**Problem**: Files won't decrypt  
**Solution**: Ensure you're using the correct master password.

**Problem**: LDAP authentication fails  
**Solution**: Check LDAP connection + credentials in `.env`.

---

## 🔄 Updates

Pull the latest version:
```bash
git pull origin main
docker-compose down
docker-compose up --build -d
```

---

**Built with ❤️ for privacy and security.**
