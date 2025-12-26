# CernCloud.Nas - Zero-Knowledge Network Attached Storage

A secure, zero-knowledge encrypted NAS system with client-side encryption. Files are encrypted in the browser before upload, ensuring the server never has access to encryption keys or plaintext data.

---

## 📺 Demo
<p align="center">
  <video src="https://github.com/user-attachments/assets/0d8faa90-e0ff-482b-aab8-356401fe43bb" width="100%" controls>
    Your browser does not support the video tag.
  </video>
</p>

---

[Français](#francais)

---

## Key Features

- **Zero-Knowledge Architecture**: Server never sees unencrypted data or keys
- **Client-Side Encryption**: AES-256-GCM + X25519/EC P-256 ECDH
- **Multi-Device Support**: Authorize new devices with cryptographic signatures (Ed25519)
- **File Versioning**: Automatic version history with rollback capability
- **Two Security Modes**:
  - Standard: EC P-256 (ECDH) + AES-256-GCM with server-side decryption
  - Maximum: X25519 (Curve25519-ECDH) + AES-256-GCM with client-side only decryption
- **LDAP Authentication**: Enterprise-ready user directory (OpenLDAP)
- **Activity Logging**: Comprehensive audit trails in SQLite
- **Custom TCP Protocol**: Binary protocol for file operations on port 65432

---

## Quick Start

### Prerequisites
- Docker & Docker Compose
- 2GB RAM minimum
- Linux/macOS/Windows (WSL2)

### Installation

**IMPORTANT**: The project is currently under active development on the `dev` branch. Use the `dev` branch for testing until it's merged into `main`.

**Option 1: Automated Script (Recommended)**

```bash
git clone https://github.com/Cern667/cernDriveSecure.git
cd cernDriveSecure
git checkout dev  # Use dev branch (active development)
./start.sh        # Creates .env, generates SECRET_KEY, starts containers
```

Access: `http://localhost:5000`

**Option 2: Manual Setup**

```bash
git clone https://github.com/Cern667/cernDriveSecure.git
cd cernDriveSecure
git checkout dev  # Use dev branch
cp .env.example .env
nano .env         # Edit SECRET_KEY and passwords
docker-compose up -d
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

### Multi-Container Docker Setup

The system runs three containers orchestrated by Docker Compose:

1. **ldap** (OpenLDAP): User directory and authentication (port 389)
2. **server** (Storage Server): TCP socket server on port 65432 for file storage
3. **client** (Flask Web Client): Web UI on port 5000

### Technology Stack
- **Frontend**: Vanilla JavaScript with Web Crypto API
- **Backend**: Python 3.11 + Flask (~2867 lines in app.py)
- **Storage**: Custom TCP binary protocol server
- **Authentication**: OpenLDAP with LDIF bootstrap
- **Database**: SQLite (activity logs, device registry)
- **Encryption**: X25519/EC P-256 (ECDH) + AES-256-GCM

### Key Components

**Backend (Python 3.11)**
- `web_client/app.py`: Flask application - main entry point for web UI
- `storage_server/server.py`: TCP socket server handling file operations
- `lib/auth/`: Device manager, security levels, QR authorization (6-digit codes)
- `lib/crypto/`: X25519/EC P-256 encryption, key management
- `lib/monitoring/`: Activity logging, admin security monitoring

**Frontend (Browser)**
- Client-side encryption using Web Crypto API
- JavaScript modules: `crypto_client.js`, `device_crypto.js`, `device_fingerprint.js`

**Infrastructure**
- LDAP authentication with fallback to LDIF import
- SQLite for metadata (activity logs, device registry)
- File storage with automatic versioning in `.versions/` subdirectories

### Project Structure

```
cernDriveSecure/
├── docker-compose.yml          # Multi-container orchestration (ldap, server, client)
├── Dockerfile                  # Multi-stage build for Python services
├── .env.example                # Configuration template (SECRET_KEY, LDAP, ports)
├── start.sh                    # Automated deployment script
├── .gitignore                  # Excludes .env, volumes, Python cache
│
├── scripts/
│   ├── generate_secret.py      # Generate Flask SECRET_KEY (secrets.token_hex)
│   └── cleanup.sh              # Docker cleanup utility (stop/clean/purge)
│
├── lib/                        # Shared Python libraries
│   ├── auth/
│   │   ├── device_manager.py   # Device registry and authorization logic
│   │   ├── qr_authorization.py # 6-digit temporary codes (60s expiry)
│   │   └── security_manager.py # Per-user security levels and key migration
│   ├── crypto/
│   │   ├── client_crypto.py    # X25519/EC P-256 encryption (backend)
│   │   ├── crypto_utils.py     # Legacy crypto utilities
│   │   └── device_keys.py      # Device cryptographic key management
│   └── monitoring/
│       ├── activity_logger.py  # Audit trail for all user actions (SQLite)
│       └── admin_security.py   # Admin-specific security monitoring
│
├── web_client/                 # Flask web application
│   ├── app.py                  # Main Flask app (~2867 lines)
│   ├── static/
│   │   └── js/
│   │       ├── crypto_client.js      # Client-side AES-256-GCM + ECDH
│   │       ├── device_crypto.js      # Device authorization crypto
│   │       └── device_fingerprint.js # Unique device identification
│   └── templates/              # HTML Jinja2 templates
│
├── storage_server/
│   └── server.py               # TCP server (port 65432) - custom binary protocol
│                               # Commands: F(upload), G(download), L(list),
│                               # V(versions), R(restore), D(delete), etc.
│
├── ldap_bootstrap/
│   └── 01-users.ldif           # Initial LDAP users (imported on first startup)
│
└── volumes/ (created at runtime)
    ├── user_keys/              # User public keys + encrypted private keys
    ├── storage/                # Encrypted files (.enc + .key)
    │   └── .versions/          # Versioned files per user/filename/timestamp
    └── data/                   # SQLite databases (activity logs, devices)
```

### Cryptographic Architecture

**Two Security Levels:**

1. **Standard Mode**: EC P-256 (ECDH) + AES-256-GCM
   - Private key encrypted with password, stored on server
   - Server decrypts files on demand
   - Compatible with all modern browsers

2. **Maximum Mode**: X25519 (Curve25519-ECDH) + AES-256-GCM
   - Private key NEVER leaves the browser
   - All decryption client-side only
   - Requires Web Crypto API with X25519 support

**Encryption Flow (File Upload):**
1. User generates asymmetric keypair (X25519 or EC P-256) in browser
2. Private key encrypted with user password using PBKDF2 (100,000 iterations)
3. Public key sent to server, encrypted private key stored on server
4. For each file upload:
   - Generate random AES-256 key
   - Encrypt file with AES-256-GCM → `file.enc`
   - Encrypt AES key with recipient's public key (ECDH) → `file.key`
   - Upload both `file.enc` and `file.key` to storage server

**Decryption Flow (File Download):**
1. Download `file.enc` + `file.key` from storage server
2. Decrypt AES key using private key (ECDH shared secret)
3. Decrypt file content with recovered AES-256 key
4. Browser downloads plaintext file (never touches server)

**Key Modules:**
- `lib/crypto/client_crypto.py` - Backend X25519/EC P-256 encryption (storage_server/server.py:84)
- `web_client/static/js/crypto_client.js` - Browser-side Web Crypto API implementation

### TCP Protocol Specification

The storage server (`storage_server/server.py`) uses a custom binary protocol:

**Message Format:** `[1 byte command][4 bytes username length][username][payload]`

**Commands:**
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

**Path Traversal Protection:**
All file paths validated with `safe_join()` in `storage_server/server.py:84` to prevent `../` attacks.

### Authentication & Device Management

**LDAP Integration:**
- Direct bind authentication (no group lookups required)
- Users imported from `ldap_bootstrap/01-users.ldif` on first startup
- Configurable via `.env` variables (LDAP_DOMAIN, LDAP_BASE_DN, etc.)

**Multi-Device Authorization:**
- First device = master device (trust anchor)
- Additional devices authorized via:
  1. 6-digit temporary code (60 second expiry)
  2. Ed25519 cryptographic signatures for verification
  3. Device fingerprinting for unique identification
- Device registry tracked in SQLite (`lib/auth/device_manager.py`)

### Zero-Knowledge Guarantees

**What Server Stores:**
- Encrypted private keys (PBKDF2-protected with user password)
- Public keys (EC P-256 or X25519)
- Encrypted files (`.enc`)
- Encrypted AES keys (`.key`)
- Metadata only: filenames, timestamps, directory structure

**What Server NEVER Sees:**
- User passwords
- Plaintext private keys
- Plaintext file contents
- Plaintext AES keys

**Security Implications:**
- Password loss = permanent data loss (no recovery mechanism by design)
- Filenames, sizes, timestamps are NOT encrypted (visible to server)
- Network traffic should use TLS in production

### File Versioning

- Automatic versioning on file overwrite
- Versions stored in `.versions/<username>/<filename>/<timestamp>.enc`
- Both `.enc` and `.key` files versioned together
- Admin can delete old versions via `X` command to save storage space

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

### Testing

```bash
# Run crypto tests
docker exec -it nas_client python3 /app/lib/crypto/client_crypto.py

# Run device manager tests
docker exec -it nas_client python3 /app/lib/auth/device_manager.py

# Test LDAP connection
docker exec -it nas_ldap ldapsearch -x -H ldap://localhost -b "dc=nas,dc=local" \
  -D "cn=admin,dc=nas,dc=local" -w ${LDAP_ADMIN_PASSWORD}
```

**Testing approach:**
- Manual testing for UI flows and encryption/decryption
- Module tests embedded in Python files (run with `if __name__ == "__main__"`)
- Test both security levels (Standard and Maximum) when modifying crypto
- Test multi-device flows with multiple browsers/devices
- Verify audit logs after operations

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

---
---

# <a name="francais"></a>Version Française

## CernCloud.Nas - Stockage Réseau à Connaissance Nulle

Système NAS sécurisé avec chiffrement zero-knowledge. Les fichiers sont chiffrés dans le navigateur avant l'upload, garantissant que le serveur n'a jamais accès aux clés de chiffrement ou aux données en clair.

---

## Démarrage Rapide

### Installation

**IMPORTANT**: Le projet est actuellement en développement actif sur la branche `dev`. Utilisez la branche `dev` pour les tests jusqu'à ce qu'elle soit fusionnée dans `main`.

```bash
git clone https://github.com/Cern667/cernDriveSecure.git
cd cernDriveSecure
git checkout dev  # Utiliser la branche dev (développement actif)
./start.sh        # Crée .env, génère SECRET_KEY, démarre les conteneurs
```

Accédez à: `http://localhost:5000`

### Comptes de Test par Défaut

Le système est livré avec **4 comptes de test** préconfigurés dans `ldap_bootstrap/01-users.ldif`:

| Username | Password | Rôle |
|----------|----------|------|
| **admin** | admin123 | Administrateur (privilèges spéciaux) |
| alice | alice123 | Utilisateur standard |
| bob | bob123 | Utilisateur standard |
| charlie | charlie123 | Utilisateur standard |

**IMPORTANT**:
- Ces comptes sont pour le **test uniquement**
- Changez les mots de passe dans `ldap_bootstrap/01-users.ldif` avant le premier démarrage en production
- Le fichier LDIF n'est importé qu'au premier lancement (si LDAP est vide)

### Création de Nouveaux Utilisateurs

Il existe **deux méthodes** pour créer des utilisateurs:

#### Méthode 1: Via l'Interface Web (Recommandé)

1. Connectez-vous en tant qu'**admin** (`admin` / `admin123`)
2. Allez dans la section **"Utilisateurs"** ou **"Gestion des utilisateurs"**
3. Cliquez sur **"Créer un utilisateur"**
4. Remplissez les informations:
   - Nom d'utilisateur (username)
   - Prénom et nom
   - Email
   - Mot de passe
5. Le nouvel utilisateur est créé dans LDAP et peut immédiatement se connecter

#### Méthode 2: Édition Manuelle du LDIF (Pour Configuration Initiale)

1. Éditez `ldap_bootstrap/01-users.ldif` **avant le premier démarrage**
2. Ajoutez un nouveau bloc utilisateur:

```ldif
dn: uid=nouveauuser,ou=users,dc=nas,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: nouveauuser
cn: Nouveau User
sn: User
givenName: Nouveau
mail: nouveauuser@nas.local
uidNumber: 1004
gidNumber: 1004
homeDirectory: /home/nouveauuser
loginShell: /bin/bash
userPassword: motdepasse123
```

3. Redémarrez les conteneurs:
```bash
docker-compose down
docker-compose up -d
```

**Note**: Les utilisateurs ajoutés manuellement au LDIF ne seront importés que si LDAP est vide (premier lancement).

---

## Architecture

### Configuration Docker Multi-Conteneurs

Le système fonctionne avec 3 conteneurs orchestrés par Docker Compose:

1. **ldap** (OpenLDAP): Annuaire utilisateurs et authentification (port 389)
2. **server** (Serveur de Stockage): Serveur socket TCP sur le port 65432 pour le stockage des fichiers
3. **client** (Client Web Flask): Interface web sur le port 5000

### Architecture Cryptographique

**Deux Niveaux de Sécurité:**

1. **Mode Standard**: EC P-256 (ECDH) + AES-256-GCM
   - Clé privée chiffrée avec mot de passe, stockée sur serveur
   - Serveur déchiffre les fichiers à la demande
   - Compatible avec tous les navigateurs modernes

2. **Mode Maximum**: X25519 (Curve25519-ECDH) + AES-256-GCM
   - Clé privée NE QUITTE JAMAIS le navigateur
   - Tout le déchiffrement se fait côté client uniquement
   - Nécessite Web Crypto API avec support X25519

**Flux de Chiffrement (Upload):**
1. L'utilisateur génère une paire de clés asymétriques (X25519 ou EC P-256) dans le navigateur
2. Clé privée chiffrée avec mot de passe utilisateur via PBKDF2 (100 000 itérations)
3. Clé publique envoyée au serveur, clé privée chiffrée stockée sur serveur
4. Pour chaque fichier uploadé:
   - Génération d'une clé AES-256 aléatoire
   - Chiffrement du fichier avec AES-256-GCM → `fichier.enc`
   - Chiffrement de la clé AES avec la clé publique du destinataire (ECDH) → `fichier.key`
   - Upload de `fichier.enc` et `fichier.key` vers le serveur

**Flux de Déchiffrement (Download):**
1. Téléchargement de `fichier.enc` + `fichier.key` depuis le serveur
2. Déchiffrement de la clé AES avec la clé privée (secret partagé ECDH)
3. Déchiffrement du contenu du fichier avec la clé AES-256 récupérée
4. Le navigateur télécharge le fichier en clair (ne touche jamais le serveur)

### Protocole TCP Personnalisé

Le serveur de stockage (`storage_server/server.py`) utilise un protocole binaire personnalisé:

**Format de Message:** `[1 octet commande][4 octets longueur username][username][payload]`

**Commandes:**
- `F`: Upload fichier
- `K`: Upload clé publique
- `P`: Download clé publique
- `L`: Lister fichiers
- `G`: Download fichier
- `V`: Lister versions
- `R`: Restaurer version
- `D`: Supprimer fichier
- `M`: Supprimer dossier
- `X`: Supprimer version (admin uniquement)
- `E`: Terminer connexion

### Garanties Zero-Knowledge

**Ce que le Serveur Stocke:**
- Clés privées chiffrées (protégées par mot de passe PBKDF2)
- Clés publiques (EC P-256 ou X25519)
- Fichiers chiffrés (`.enc`)
- Clés AES chiffrées (`.key`)
- Métadonnées uniquement: noms de fichiers, timestamps, structure de répertoires

**Ce que le Serveur NE VOIT JAMAIS:**
- Mots de passe utilisateurs
- Clés privées en clair
- Contenu des fichiers en clair
- Clés AES en clair

**Implications de Sécurité:**
- Perte de mot de passe = perte permanente des données (aucun mécanisme de récupération par conception)
- Les noms de fichiers, tailles, timestamps ne sont PAS chiffrés (visibles par le serveur)
- Le trafic réseau devrait utiliser TLS en production

---

## Utilisation

### Configuration Initiale (Premier Appareil)

1. Connectez-vous sur `http://localhost:5000`
2. Cliquez sur "Générer mes clés de chiffrement"
3. Choisissez le niveau de sécurité (Standard ou Maximum)
4. Créez un mot de passe maître fort
5. Sauvegardez le mot de passe en lieu sûr - **irrécupérable si perdu**

### Ajout d'un Nouvel Appareil

**Sur le nouvel appareil:**
1. Connectez-vous avec vos identifiants LDAP
2. Un code à 6 chiffres s'affiche (valide 60 secondes)

**Sur un appareil de confiance:**
1. Allez dans "Connexion appareil" ou "Gestion des appareils"
2. Entrez le code à 6 chiffres
3. Approuvez l'autorisation

**Retour sur le nouvel appareil:**
1. Entrez votre mot de passe maître
2. L'appareil est maintenant autorisé

### Opérations sur les Fichiers

**Upload:**
1. Allez dans "Mes Fichiers"
2. Glissez-déposez ou sélectionnez des fichiers
3. Les fichiers sont automatiquement chiffrés avant l'upload

**Téléchargement:**
- **Mode standard**: Cliquez sur télécharger (déchiffrement sur serveur)
- **Mode maximum**: Entrez le mot de passe (déchiffrement dans navigateur)

**Versioning:**
- Les fichiers sont automatiquement versionnés lors de l'écrasement
- Voir les versions dans l'onglet "Versions"
- Télécharger ou restaurer des versions précédentes

---

## Sécurité

### Bonnes Pratiques

1. **Utilisez des mots de passe forts**: Le mot de passe maître chiffre votre clé privée
2. **Activez le mode Maximum**: Pour la sécurité maximale (côté client uniquement)
3. **Sauvegardez les mots de passe**: Utilisez un gestionnaire de mots de passe
4. **Changez les identifiants par défaut**: Modifiez les mots de passe dans `ldap_bootstrap/01-users.ldif`
5. **Générez une SECRET_KEY forte**: Utilisez `scripts/generate_secret.py`
6. **Révoquez les appareils compromis**: Depuis l'interface "Connexion appareil"

### Déploiement en Production

1. Utilisez HTTPS/TLS pour toutes les connexions
2. Changez tous les mots de passe par défaut:
   - Éditez `ldap_bootstrap/01-users.ldif` **avant le premier lancement**
   - Changez `LDAP_ADMIN_PASSWORD` dans `.env`
3. Générez une `SECRET_KEY` unique par déploiement
4. Implémentez l'isolation réseau (règles pare-feu)
5. Sauvegardes régulières des données chiffrées
6. Surveillez les journaux d'activité pour les comportements suspects

---

## Développement

### Commandes Utiles

```bash
# Voir les logs
docker-compose logs -f
docker-compose logs -f client
docker-compose logs -f server

# Redémarrer un service
docker-compose restart client

# Rebuild après changements de code
docker-compose up --build -d

# Accéder au shell du conteneur
docker exec -it nas_client /bin/bash
```

### Ajout d'Utilisateurs (Méthode Manuelle)

Éditez `ldap_bootstrap/01-users.ldif` et redémarrez:

```bash
docker-compose down
docker-compose up -d
```

**Attention**: Les utilisateurs ne sont importés que si LDAP est vide (premier lancement uniquement).

---

## Dépannage

**"Code invalide" lors de l'autorisation d'appareil:**
- Les codes expirent après 60 secondes
- Vérifiez la synchronisation de l'horloge système
- Régénérez un code s'il a expiré

**Les fichiers ne se déchiffrent pas:**
- Vérifiez que le mot de passe est correct
- Vérifiez que le niveau de sécurité correspond au type de clé
- Consultez la console du navigateur pour les erreurs

**Échec de l'authentification LDAP:**
- Vérifiez le conteneur LDAP: `docker-compose ps`
- Vérifiez les identifiants dans `.env`
- Testez le bind LDAP: `docker exec nas_ldap ldapsearch -x -H ldap://localhost`

**Connexion au serveur de stockage refusée:**
- Vérifiez les logs du serveur: `docker-compose logs server`
- Vérifiez `STORAGE_SERVER_IP` et `STORAGE_SERVER_PORT` dans `.env`

---

## Structure du Projet

```
cernDriveSecure/
├── docker-compose.yml          # Orchestration multi-conteneurs (ldap, server, client)
├── Dockerfile                  # Build multi-étapes pour services Python
├── .env.example                # Template de configuration (SECRET_KEY, LDAP, ports)
├── start.sh                    # Script de déploiement automatisé
├── .gitignore                  # Exclut .env, volumes, cache Python
│
├── scripts/
│   ├── generate_secret.py      # Génère Flask SECRET_KEY (secrets.token_hex)
│   └── cleanup.sh              # Utilitaire de nettoyage Docker (stop/clean/purge)
│
├── lib/                        # Bibliothèques Python partagées
│   ├── auth/
│   │   ├── device_manager.py   # Registre et logique d'autorisation des appareils
│   │   ├── qr_authorization.py # Codes temporaires à 6 chiffres (expiration 60s)
│   │   └── security_manager.py # Niveaux de sécurité par utilisateur et migration clés
│   ├── crypto/
│   │   ├── client_crypto.py    # Chiffrement X25519/EC P-256 (backend)
│   │   ├── crypto_utils.py     # Utilitaires crypto legacy
│   │   └── device_keys.py      # Gestion des clés cryptographiques d'appareil
│   └── monitoring/
│       ├── activity_logger.py  # Piste d'audit pour toutes actions utilisateur (SQLite)
│       └── admin_security.py   # Surveillance sécurité spécifique admin
│
├── web_client/                 # Application web Flask
│   ├── app.py                  # Application Flask principale (~2867 lignes)
│   ├── static/
│   │   └── js/
│   │       ├── crypto_client.js      # AES-256-GCM + ECDH côté client
│   │       ├── device_crypto.js      # Crypto d'autorisation d'appareil
│   │       └── device_fingerprint.js # Identification unique d'appareil
│   └── templates/              # Templates HTML Jinja2
│
├── storage_server/
│   └── server.py               # Serveur TCP (port 65432) - protocole binaire custom
│                               # Commandes: F(upload), G(download), L(list),
│                               # V(versions), R(restore), D(delete), etc.
│
├── ldap_bootstrap/
│   └── 01-users.ldif           # Utilisateurs LDAP initiaux (importés au premier lancement)
│
└── volumes/ (créés au runtime)
    ├── user_keys/              # Clés publiques + clés privées chiffrées utilisateur
    ├── storage/                # Fichiers chiffrés (.enc + .key)
    │   └── .versions/          # Fichiers versionnés par user/filename/timestamp
    └── data/                   # Bases de données SQLite (logs activité, appareils)
```

---

---

[⬆ Retour en haut](#cerncloudnas---zero-knowledge-network-attached-storage)
