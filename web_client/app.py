from flask import Flask, render_template, request, session, redirect, url_for, send_from_directory, jsonify, send_file
from functools import wraps
from dotenv import load_dotenv
import socket
import os
import struct
import zipfile
import tempfile

import sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from lib.crypto.crypto_utils import chiffrer_fichier as chiffrer_fichier_legacy, dechiffrer_fichier as dechiffrer_fichier_legacy
from lib.crypto.client_crypto import chiffrer_fichier_complet, dechiffrer_fichier_complet
from lib.auth.security_manager import get_security_manager, SECURITY_LEVEL_STANDARD, SECURITY_LEVEL_MAXIMUM

# Import du module activity_logger depuis le répertoire parent
try:
    from lib.monitoring.activity_logger import get_activity_logger
except ImportError:
    # If import fails, add parent path and retry
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)
    from lib.monitoring.activity_logger import get_activity_logger

import re

# Charger les variables d'environnement
load_dotenv()

app = Flask(__name__)
APP_PORT = int(os.environ.get('FLASK_PORT', '5000'))

# =============================
# FLASK & LDAP CONFIGURATION
# =============================
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersecretkey")

# Configuration LDAP dynamique par variable d'environnement
app.config['LDAP_HOST'] = os.environ.get('FLASK_LDAP_HOST', 'ldap://127.0.0.1:389')
app.config['LDAP_BASE_DN'] = os.environ.get('FLASK_LDAP_BASE_DN', 'dc=mondomaine,dc=com')
app.config['LDAP_USER_DN'] = os.environ.get('FLASK_LDAP_USER_DN', 'ou=users')
app.config['LDAP_USER_RDN_ATTR'] = os.environ.get('FLASK_LDAP_USER_RDN_ATTR', 'uid')
app.config['LDAP_USER_SEARCH_FILTER'] = os.environ.get('FLASK_LDAP_USER_SEARCH_FILTER', '(uid={username})')
app.config['LDAP_USER_LOGIN_ATTR'] = os.environ.get('FLASK_LDAP_USER_LOGIN_ATTR', 'uid')
app.config['LDAP_BIND_USER_DN'] = os.environ.get('FLASK_LDAP_BIND_USER_DN', 'cn=admin,dc=mondomaine,dc=com')
app.config['LDAP_BIND_USER_PASSWORD'] = os.environ.get('FLASK_LDAP_BIND_USER_PASSWORD', 'admin')
app.config['LDAP_USE_SSL'] = os.environ.get('FLASK_LDAP_USE_SSL', 'False').lower() in ('true', '1', 'yes')
app.config['LDAP_PORT'] = int(os.environ.get('FLASK_LDAP_PORT', '389'))

# Normaliser FLASK_LDAP_HOST pour accepter ldap://host:port et ldaps://host:port
def _parse_ldap_host(value: str):
    try:
        m = re.match(r'^(ldap|ldaps)://([^/:]+)(?::(\d+))?$', value.strip())
        if m:
            scheme, host, port = m.group(1), m.group(2), m.group(3)
            use_ssl = (scheme == 'ldaps')
            port = int(port) if port else (636 if use_ssl else 389)
            return host, port, use_ssl
        m2 = re.match(r'^([^:]+):(\d+)$', value.strip())
        if m2:
            return m2.group(1), int(m2.group(2)), None
        return value.strip(), None, None
    except Exception:
        return value.strip(), None, None

_host, _port_from_url, _ssl_from_url = _parse_ldap_host(app.config['LDAP_HOST'])
app.config['LDAP_HOST'] = _host
if _port_from_url:
    app.config['LDAP_PORT'] = _port_from_url
if _ssl_from_url is not None:
    app.config['LDAP_USE_SSL'] = _ssl_from_url

app.config['ADMIN_USERNAME'] = os.environ.get('ADMIN_USERNAME', 'admin')
USE_MOCK_LDAP = os.environ.get('FLASK_USE_MOCK_LDAP', 'False').lower() in ('true', '1', 'yes')
FALLBACK_TO_LDIF = os.environ.get('FLASK_LDAP_FALLBACK_TO_LDIF', 'True').lower() in ('true', '1', 'yes')

# Répertoires upload/download
app.config['UPLOAD_FOLDER'] = 'temp_uploads'
app.config['DOWNLOAD_FOLDER'] = 'temp_downloads'

STORAGE_SERVER_IP = os.environ.get("STORAGE_SERVER_IP", "storage_server")
STORAGE_SERVER_PORT = int(os.environ.get("STORAGE_SERVER_PORT", "65432"))

# Chemins absolus pour Docker
USER_KEYS_DIR = '/app/user_keys'
STORAGE_DIR = '/app/storage'

# Initialiser le gestionnaire LDAP avec authentification directe (sans flask-ldap3-login groups)
from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.core.exceptions import LDAPBindError, LDAPException

def ldap_authenticate(username, password):
    """Authentification LDAP directe sans recherche de groupes."""
    if not username or not password:
        return False
    try:
        host = app.config['LDAP_HOST']
        port = app.config['LDAP_PORT']
        use_ssl = app.config['LDAP_USE_SSL']
        base_dn = app.config['LDAP_BASE_DN']
        user_dn = app.config['LDAP_USER_DN']
        bind_dn = app.config['LDAP_BIND_USER_DN']
        bind_pwd = app.config['LDAP_BIND_USER_PASSWORD']

        server = Server(host, port=port, use_ssl=use_ssl, get_info=ALL)

        # Admin bind pour rechercher l'utilisateur
        admin_conn = Connection(server, bind_dn, bind_pwd, auto_bind=True)
        search_base = f"{user_dn},{base_dn}"
        admin_conn.search(search_base, f"(uid={username})", SUBTREE)

        if not admin_conn.entries:
            admin_conn.unbind()
            return False

        user_full_dn = admin_conn.entries[0].entry_dn
        admin_conn.unbind()

        # User bind pour vérifier le mot de passe
        user_conn = Connection(server, user_full_dn, password, auto_bind=True)
        user_conn.unbind()
        return True

    except LDAPBindError:
        return False
    except LDAPException as e:
        print(f"[LDAP] Exception: {e}")
        return False
    except Exception as e:
        print(f"[LDAP] Unexpected error: {e}")
        return False

# =========================================
# MOCK LDAP (optional for local demo)
# =========================================
def load_ldif_users(ldif_path):
    users = {}
    current = {}
    current_dn = None
    if not os.path.exists(ldif_path):
        return users
    with open(ldif_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                # fin d’entrée
                if current_dn:
                    # extrait username
                    # cas admin: dn: cn=admin,...
                    m_uid = re.search(r'uid=([^,]+)', current_dn)
                    m_cn = re.search(r'cn=([^,]+)', current_dn)
                    username = None
                    if m_uid:
                        username = m_uid.group(1).lower()
                    elif m_cn:
                        username = m_cn.group(1).lower()
                    if username and 'userPassword' in current:
                        users[username] = current['userPassword']
                current = {}
                current_dn = None
                continue
            if line.lower().startswith('dn:'):
                current_dn = line.split(':', 1)[1].strip()
                continue
            if ':' in line:
                k, v = line.split(':', 1)
                current[k.strip()] = v.strip()
        # flush dernière entrée
        if current_dn:
            m_uid = re.search(r'uid=([^,]+)', current_dn)
            m_cn = re.search(r'cn=([^,]+)', current_dn)
            username = m_uid.group(1).lower() if m_uid else (m_cn.group(1).lower() if m_cn else None)
            if username and 'userPassword' in current:
                users[username] = current['userPassword']
    return users

def mock_authenticate(username, password):
    ldif_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ldap', 'config', 'users.ldif')
    users = load_ldif_users(ldif_path)
    expected = users.get(username)
    return expected is not None and expected == password

# =========================================
# SOCKET COMMUNICATION UTILITIES
# =========================================
def send_prefixed_string(sock, text):
    text_bytes = text.encode('utf-8')
    sock.sendall(struct.pack('!I', len(text_bytes)))
    sock.sendall(text_bytes)

def start_command(sock, command, username):
    sock.sendall(command.encode('utf-8'))
    send_prefixed_string(sock, username)

# =========================================
# AUTHENTICATION & DECORATORS
# =========================================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# =========================================
# HEALTHCHECK
# =========================================
@app.route('/healthz', methods=['GET'])
def healthz():
    return 'ok', 200

# =========================================
# LDAP HEALTH
# =========================================
@app.route('/ldap/health', methods=['GET'])
def ldap_health():
    host = app.config.get('LDAP_HOST')
    port = app.config.get('LDAP_PORT')
    try:
        with socket.create_connection((host, port), timeout=2):
            return f"ldap reachable on {host}:{port}", 200
    except Exception as e:
        return f"ldap unreachable on {host}:{port} ({e})", 503

# =========================================
# LOGIN ROUTE
# =========================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username, password = request.form['username'], request.form['password']
        # Normaliser le nom d'utilisateur en minuscules pour éviter les doublons
        username = username.lower().strip()
        print("[LDAP] Tentative:", username)

        # Get IP and user agent for logging
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        logger = get_activity_logger()

        if USE_MOCK_LDAP:
            ok = mock_authenticate(username, password)
            print("[MOCK LDAP]", "success" if ok else "failure")
            if ok:
                session['logged_in'] = True
                session['username'] = username
                print(f"[MOCK] User {username} connected successfully.")

                # Logger la connexion réussie
                logger.log_activity(username, 'LOGIN', ip_address, 'SUCCESS',
                                  'Connexion réussie (MOCK LDAP)', user_agent=user_agent)

                # Check if keys exist
                if not user_has_keys(username):
                    return redirect(url_for('setup_keys'))
                return redirect(url_for('index'))
            print(f"[MOCK] Authentication failed for {username}.")

            # Logger l'échec de connexion
            logger.log_activity(username, 'LOGIN_FAILED', ip_address, 'FAILED',
                              'Identifiants invalides', user_agent=user_agent)

            return render_template('login.html', error='Identifiants invalides (mock).')
        else:
            # Authentification LDAP directe
            try:
                with socket.create_connection((app.config['LDAP_HOST'], app.config['LDAP_PORT']), timeout=2):
                    pass
            except Exception:
                if FALLBACK_TO_LDIF:
                    print("[LDAP] Injoignable; bascule LDIF fallback")
                    ok = mock_authenticate(username, password)
                    if ok:
                        session['logged_in'] = True
                        session['username'] = username
                        # Check if keys exist
                        if not user_has_keys(username):
                            return redirect(url_for('setup_keys'))
                        return redirect(url_for('index'))
                return render_template('login.html', error='LDAP injoignable.')

            if ldap_authenticate(username, password):
                session['logged_in'] = True
                session['username'] = username
                print(f"[LOGIN] User {username} connected.")

                # Logger la connexion réussie
                logger.log_activity(username, 'LOGIN', ip_address, 'SUCCESS',
                                  'Connexion réussie', user_agent=user_agent)

                # ADMIN: direct access without keys
                if username == app.config['ADMIN_USERNAME']:
                    print(f"[ADMIN] {username} → Accès direct")
                    return redirect(url_for('index'))

                # USERS : Vérifier le niveau de sécurité
                security_mgr = get_security_manager()
                security_level = security_mgr.get_user_security_level(username)

                # If user doesn't have a security level yet, use global mode
                if username not in security_mgr.users_security:
                    import sys
                    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                    if parent_dir not in sys.path:
                        sys.path.insert(0, parent_dir)
                    from lib.monitoring.admin_security import get_current_mode

                    global_mode = get_current_mode()
                    security_level = SECURITY_LEVEL_MAXIMUM if global_mode == 'maximum' else SECURITY_LEVEL_STANDARD

                    # Enregistrer le niveau pour cet utilisateur
                    security_mgr.set_user_security_level(username, security_level)
                    print(f"[SECURITY] {username} → Nouveau user, niveau hérité du mode global: {security_level}")
                else:
                    print(f"[SECURITY] {username} → Niveau: {security_level}")
                
                if security_level == SECURITY_LEVEL_MAXIMUM:
                    # Mode maximum : zero-knowledge obligatoire
                    import sys
                    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
                    from lib.auth.device_manager import has_registered_key, has_compatible_keys, get_user_key_type

                    has_keys = has_registered_key(username)

                    # IMPORTANT: Check that keys are the right type (X25519 for maximum mode)
                    if has_keys:
                        key_type = get_user_key_type(username)
                        is_compatible = has_compatible_keys(username, 'maximum')

                        if not is_compatible:
                            # Clés incompatibles (EC au lieu de X25519) → Forcer régénération
                            print(f"[SECURITY MAX] WARNING: {username} → Incompatible keys (type: {key_type}, expected: X25519)")
                            print(f"[SECURITY MAX] {username} → Redirection vers setup pour régénération")

                            # Supprimer les anciennes clés incompatibles
                            user_key_dir = os.path.join('/app/user_keys', username)
                            if os.path.exists(user_key_dir):
                                import shutil
                                shutil.rmtree(user_key_dir)
                                os.makedirs(user_key_dir)
                                print(f"[SECURITY MAX] Old {key_type} keys deleted for {username}")

                            return redirect(url_for('setup_keys'))

                    if not has_keys:
                        # Premier appareil → Setup zero-knowledge
                        print(f"[SECURITY MAX] {username} → Redirection vers setup zero-knowledge")
                        return redirect(url_for('setup_keys'))
                    else:
                        # User a déjà des clés compatibles → Vérifier si CET appareil est autorisé
                        from lib.auth.device_manager import is_device_authorized

                        # Générer l'empreinte de l'appareil actuel
                        user_agent = request.headers.get('User-Agent', '')
                        accept_language = request.headers.get('Accept-Language', '')
                        device_fingerprint_data = f"{user_agent}|{accept_language}"
                        import hashlib
                        device_fingerprint = hashlib.sha256(device_fingerprint_data.encode()).hexdigest()

                        if is_device_authorized(username, device_fingerprint):
                            # Appareil déjà autorisé → Dashboard
                            print(f"[SECURITY MAX] {username} → Appareil autorisé, accès dashboard")
                            return redirect(url_for('index'))
                        else:
                            # Appareil non autorisé → QR Authorization
                            print(f"[SECURITY MAX] {username} → Appareil non autorisé, redirection vers QR")
                            return redirect(url_for('qr_request_authorization'))
                else:
                    # Mode standard : accès direct au dashboard
                    # Générer des clés basiques si elles n'existent pas (pour compatibility upload)
                    if not user_has_keys(username):
                        print(f"[SECURITY STD] {username} → Génération automatique de clés basiques")
                        _generate_basic_keys_for_user(username)
                    
                    print(f"[SECURITY STD] {username} → Accès direct au dashboard")
                    return redirect(url_for('index'))
            else:
                print(f"[LOGIN] Authentication failed for {username}")

                # Logger l'échec de connexion
                logger.log_activity(username, 'LOGIN_FAILED', ip_address, 'FAILED',
                                  'Identifiants invalides', user_agent=user_agent)

                return render_template('login.html', error='Identifiants invalides.')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# =========================================
# USER KEY SETUP
# =========================================
def user_has_keys(username):
    """Verifie si l'utilisateur a ses cles generees."""
    privkey = os.path.join(USER_KEYS_DIR, username, 'private_key.pem')
    pubkey = os.path.join(USER_KEYS_DIR, username, 'public_key.pem')
    return os.path.exists(privkey) and os.path.exists(pubkey)

@app.route('/setup-keys')
@login_required
def setup_keys():
    """Page de setup des clés (premier appareil)"""
    username = session.get('username')
    return render_template('setup_keys.html', username=username)

@app.route('/generate-keys', methods=['GET', 'POST'])
@login_required  
def generate_keys():
    """
    GET: Détecte si premier setup ou nouvel appareil nécessitant QR
    POST: Enregistre les clés du premier appareil
    """
    username = session.get('username')
    
    if request.method == 'GET':
        import sys
        sys.path.append(os.path.dirname(os.path.dirname(__file__)))
        from lib.auth.device_manager import has_registered_key, is_device_authorized
        
        # Check if user already has keys
        has_keys = has_registered_key(username)
        
        if has_keys:
            # User a déjà des clés → Vérifier si CET appareil est autorisé
            # On utilise un fingerprint temporaire côté client
            # Pour l'instant on redirige vers QR
            print(f"[QR WORKFLOW] {username} has keys, redirecting to QR authorization")
            return redirect(url_for('qr_request_authorization'))
        else:
            # Pas de clés → Setup initial (premier appareil)
            print(f"[SETUP] {username} first device, showing setup page")
            return render_template('setup_keys.html')
    
    # POST : Enregistrement des clés (premier appareil)
    data = request.get_json()
    
    encrypted_private_key = data.get('encrypted_private_key')
    salt = data.get('salt')
    iv = data.get('iv')
    public_key = data.get('public_key')
    device_info = data.get('device_info', {})
    device_fingerprint = data.get('device_fingerprint')
    device_public_key_ed25519 = data.get('device_public_key_ed25519')
    
    if not all([encrypted_private_key, salt, iv, public_key, device_fingerprint, device_public_key_ed25519]):
        return jsonify({'success': False, 'error': 'Données manquantes'}), 400
    
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    from lib.auth.device_manager import register_device, has_registered_key
    
    # Check that keys don't already exist
    if has_registered_key(username):
        return jsonify({'success': False, 'error': 'Clés déjà enregistrées'}), 400
    
    # Enregistrer le premier appareil (authorized_by = None car c'est le maître)
    result = register_device(
        username=username,
        device_fingerprint=device_fingerprint,
        device_info=device_info,
        encrypted_private_key=encrypted_private_key,
        salt=salt,
        iv=iv,
        device_public_key_ed25519=device_public_key_ed25519,
        authorized_by_device_id=None  # Premier appareil = maître
    )
    
    if not result['success']:
        return jsonify(result), 400
    
    # Sauvegarder la clé publique au format PEM
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    
    try:
        # IMPORTANT: Web Crypto API does NOT support X25519!
        # Le JavaScript génère des clés ECDH P-256 (65 bytes raw format)
        # On doit donc accepter les clés EC, pas X25519
        
        public_key_bytes = base64.b64decode(public_key)
        
        # Les clés P-256 du navigateur sont en format RAW (65 bytes non compressé)
        # On doit les convertir en objet EC pour sauvegarder en PEM
        public_key_obj = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), public_key_bytes
        )
        
        public_key_pem = public_key_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        user_keys_dir = os.path.join(USER_KEYS_DIR, username)
        os.makedirs(user_keys_dir, exist_ok=True)
        pubkey_path = os.path.join(user_keys_dir, 'public_key.pem')
        
        with open(pubkey_path, 'wb') as f:
            f.write(public_key_pem)
        
        storage_user_dir = os.path.join(STORAGE_DIR, username)
        os.makedirs(storage_user_dir,exist_ok=True)
        import shutil
        shutil.copy(pubkey_path, os.path.join(storage_user_dir, 'public_key.pem'))
        
        print(f"[KEYS ZK] P-256 (ECDH) public key saved for {username}")
        
    except Exception as e:
        print(f"[KEYS ZK] Error: {e}")
        return jsonify({'success': False,'error': str(e)}), 500
    
    logger = get_activity_logger()
    logger.log_activity(
        username, 'KEY_GENERATION', request.remote_addr,
        'SUCCESS', f'Premier appareil: {device_info.get("device_name", "Unknown")}',
        user_agent=request.headers.get('User-Agent', '')
    )
    
    return jsonify({
        'success': True,
        'device_id': result['device_id'],
        'message': 'Clés configurées'
    })

def _generate_basic_keys_for_user(username: str):
    """
    Génère automatiquement des clés X25519 pour un utilisateur en mode standard.
    Ces clés ne sont PAS protégées par mot de passe zero-knowledge.
    Le serveur garde la clé privée en clair (mode standard).
    """
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives import serialization
    import shutil
    
    user_keys_dir = os.path.join(USER_KEYS_DIR, username)
    os.makedirs(user_keys_dir, exist_ok=True)
    
    try:
        # Générer paire de clés X25519
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        # Sauvegarder clé privée (NON chiffrée, mode standard only)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Sauvegarder clé publique
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(os.path.join(user_keys_dir, 'private_key.pem'), 'wb') as f:
            f.write(private_pem)
        
        with open(os.path.join(user_keys_dir, 'public_key.pem'), 'wb') as f:
            f.write(public_pem)
        
        # Copier vers storage
        storage_user_dir = os.path.join(STORAGE_DIR, username)
        os.makedirs(storage_user_dir, exist_ok=True)
        shutil.copy(os.path.join(user_keys_dir, 'public_key.pem'), 
                    os.path.join(storage_user_dir, 'public_key.pem'))
        
        print(f"[KEYS STANDARD] Basic keys generated for {username}")
        return True
    except Exception as e:
        print(f"[KEYS STANDARD] Key generation error for {username}: {e}")
        return False

@app.route('/download-private-key')
@login_required
def download_private_key():
    """
    Télécharge la clé privée de l'utilisateur

    En mode maximum avec serveur : retourne la clé chiffrée stockée dans authorized_devices.json
    En mode standard : retourne le fichier PEM local
    """
    username = session.get('username')
    security_mgr = get_security_manager()
    security_level = security_mgr.get_user_security_level(username)

    # Mode maximum : retourner la clé chiffrée depuis authorized_devices.json
    if security_level == SECURITY_LEVEL_MAXIMUM:
        import sys
        sys.path.append(os.path.dirname(os.path.dirname(__file__)))
        from lib.auth.device_manager import get_encrypted_private_key

        key_data = get_encrypted_private_key(username)

        if not key_data or not key_data.get('encrypted_private_key'):
            return "Clé privée chiffrée introuvable. Veuillez configurer vos clés.", 404

        # Create temporary JSON file with encrypted key data
        import tempfile
        import json

        temp_dir = os.path.join(app.root_path, 'temp_downloads')
        os.makedirs(temp_dir, exist_ok=True)

        temp_path = os.path.join(temp_dir, f'{username}_encrypted_key.json')

        with open(temp_path, 'w') as f:
            json.dump({
                'username': username,
                'encrypted_private_key': key_data['encrypted_private_key'],
                'salt': key_data['salt'],
                'iv': key_data['iv'],
                'created_at': key_data.get('created_at', ''),
                'note': 'Cette clé privée est chiffrée avec votre mot de passe. Gardez ce fichier en lieu sûr.'
            }, f, indent=2)

        return send_file(
            temp_path,
            as_attachment=True,
            download_name=f'{username}_encrypted_private_key.json',
            mimetype='application/json'
        )

    # Mode standard : retourner le fichier PEM local
    privkey_path = os.path.join(USER_KEYS_DIR, username, 'private_key.pem')
    backup_path = privkey_path + '.server_backup'

    # En mode standard, la clé peut être dans le backup
    if not os.path.exists(privkey_path) and os.path.exists(backup_path):
        privkey_path = backup_path

    if not os.path.exists(privkey_path):
        return "Clé privée introuvable. Veuillez contacter l'administrateur.", 404

    return send_file(
        privkey_path,
        as_attachment=True,
        download_name=f'{username}_private_key.pem'
    )

# =========================================
# ZERO-KNOWLEDGE API
# =========================================

@app.route('/api/get-encrypted-key', methods=['GET'])
@login_required
def get_encrypted_key():
    """
    Renvoie la clé privée chiffrée de l'utilisateur pour déchiffrement côté client
    """
    username = session.get('username')
    
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    from lib.auth.device_manager import get_encrypted_private_key
    
    key_data = get_encrypted_private_key(username)
    
    if not key_data or not key_data.get('encrypted_private_key'):
        return jsonify({'success': False, 'error': 'Clé privée chiffrée introuvable'}), 404
    
    return jsonify({
        'success': True,
        'encrypted_private_key': key_data['encrypted_private_key'],
        'salt': key_data['salt'],
        'iv': key_data['iv']
    })

@app.route('/api/devices', methods=['GET'])
@login_required
def api_devices():
    """Liste les appareils autorisés de l'utilisateur"""
    username = session.get('username')
    
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    from lib.auth.device_manager import list_user_devices
    
    devices = list_user_devices(username)
    return jsonify({'success': True, 'devices': devices})

@app.route('/api/revoke-device', methods=['POST'])
@login_required
def api_revoke_device():
    """Révoque l'accès d'un appareil"""
    username = session.get('username')
    data = request.get_json()
    device_id = data.get('device_id')
    
    if not device_id:
        return jsonify({'success': False, 'error': 'Device ID manquant'}), 400
    
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    from lib.auth.device_manager import revoke_device
    
    result = revoke_device(username, device_id)
    
    # Logger l'action
    if result['success']:
        logger = get_activity_logger()
        logger.log_activity(
            username, 'DEVICE_REVOKED', request.remote_addr,
            'SUCCESS', f'Appareil révoqué: {device_id}',
            user_agent=request.headers.get('User-Agent', '')
        )
    
    return jsonify(result)


@app.route('/devices-management')
@login_required
def devices_management():
    """
    Page de gestion des appareils : voir tous les appareils, autoriser et supprimer
    """
    return render_template('devices_management.html')


# =========================================
# QR DEVICE AUTHORIZATION API
# =========================================

@app.route('/api/request-device-authorization', methods=['POST'])
@login_required
def api_request_device_authorization():
    """
    Nouvel appareil demande une autorisation via QR code
    Crée une session temporaire (60s)
    """
    username = session.get('username')
    data = request.get_json()
    
    device_fingerprint = data.get('device_fingerprint')
    device_public_key_ed25519 = data.get('device_public_key_ed25519')
    device_info = data.get('device_info', {})
    
    if not all([device_fingerprint, device_public_key_ed25519]):
        return jsonify({'success': False, 'error': 'Données manquantes'}), 400
    
    # Create authorization session
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    from lib.auth.qr_authorization import AuthorizationSession
    
    session_result = AuthorizationSession.create_session(
        username=username,
        new_device_fingerprint=device_fingerprint,
        new_device_pubkey_ed25519=device_public_key_ed25519,
        device_info=device_info,
        max_age_seconds=60
    )
    
    print(f"[QR AUTH] Session créée pour {username}: {session_result['session_id']}")
    
    return jsonify(session_result)

@app.route('/api/generate-qr-authorization', methods=['POST'])
@login_required
def api_generate_qr_authorization():
    """
    Appareil de confiance génère un QR code pour autoriser un autre appareil
    """
    username = session.get('username')
    data = request.get_json()
    
    session_id = data.get('session_id')
    
    if not session_id:
        return jsonify({'success': False, 'error': 'session_id manquant'}), 400
    
    # Get session
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    from lib.auth.qr_authorization import AuthorizationSession
    
    session_data = AuthorizationSession.get_session(session_id)
    
    if not session_data:
        return jsonify({'success': False, 'error': 'Session introuvable'}), 404
    
    if session_data['status'] == 'expired':
        return jsonify({'success': False, 'error': 'Session expirée'}), 410
    
    # Générer les données du QR code
    qr_data = {
        'session_id': session_id,
        'new_device_pubkey': session_data['new_device_pubkey_ed25519'],
        'timestamp': session_data['timestamp']
    }
    
    # Générer le QR code (image base64)
    import json
    import qrcode
    from io import BytesIO
    import base64
    
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(json.dumps(qr_data))
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
    
    return jsonify({
        'success': True,
        'qr_data': qr_data,
        'qr_code_dataurl': f'data:image/png;base64,{img_base64}'
    })

@app.route('/api/authorize-device', methods=['POST'])
@login_required
def api_authorize_device():
    """
    Appareil de confiance signe et autorise un nouvel appareil
    """
    username = session.get('username')
    data = request.get_json()
    
    session_id = data.get('session_id')
    signature = data.get('signature')
    signer_device_id = data.get('signer_device_id')
    
    if not all([session_id, signature, signer_device_id]):
        return jsonify({'success': False, 'error': 'Données manquantes'}), 400
    
    # Check that signer_device_id belongs to the user
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    from lib.auth.device_manager import list_user_devices, register_device, get_encrypted_private_key
    
    user_devices = list_user_devices(username)
    signer_device = None
    
    for device in user_devices:
        if device['device_id'] == signer_device_id and not device.get('revoked', False):
            signer_device = device
            break
    
    if not signer_device:
        return jsonify({'success': False, 'error': 'Appareil signer non autorisé'}), 403
    
    signer_pubkey = signer_device.get('device_public_key_ed25519')
    if not signer_pubkey:
        return jsonify({'success': False, 'error': 'Clé publique appareil manquante'}), 400
    
    # Autoriser la session
    from lib.auth.qr_authorization import AuthorizationSession
    
    success, message, device_info = AuthorizationSession.authorize_session(
        session_id=session_id,
        signature_base64=signature,
        signer_device_id=signer_device_id,
        signer_pubkey_ed25519=signer_pubkey
    )
    
    if not success:
        return jsonify({'success': False, 'error': message}), 400
    
    # Enregistrer le nouvel appareil
    user_key_data = get_encrypted_private_key(username)
    
    if not user_key_data:
        return jsonify({'success': False, 'error': 'Clé utilisateur introuvable'}), 500
    
    register_result = register_device(
        username=username,
        device_fingerprint=device_info['fingerprint'],
        device_info=device_info['device_info'],
        encrypted_private_key=user_key_data['encrypted_private_key'],
        salt=user_key_data['salt'],
        iv=user_key_data['iv'],
        device_public_key_ed25519=device_info['device_public_key_ed25519'],
        authorized_by_device_id=signer_device_id
    )
    
    # Logger l'action
    logger = get_activity_logger()
    logger.log_activity(
        username, 'DEVICE_AUTHORIZED', request.remote_addr,
        'SUCCESS', f'Nouvel appareil autorisé via QR: {register_result["device_id"]}',
        user_agent=request.headers.get('User-Agent', '')
    )
    
    print(f"[QR AUTH] New device authorized for {username}: {register_result['device_id']}")
    
    return jsonify({
        'success': True,
        'message': 'Appareil autorisé',
        'new_device_id': register_result['device_id']
    })

@app.route('/api/check-authorization-status', methods=['GET'])
def api_check_authorization_status():
    """
    Vérifie le statut d'une session d'autorisation (polling)
    """
    session_id = request.args.get('session_id')
    
    if not session_id:
        return jsonify({'error': 'session_id manquant'}), 400
    
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    from lib.auth.qr_authorization import AuthorizationSession
    
    status = AuthorizationSession.check_authorization_status(session_id)
    
    return jsonify(status)

@app.route('/qr-request-authorization')
@login_required
def qr_request_authorization():
    """
    Page pour nouvel appareil : affiche code 6 chiffres
    """
    return render_template('qr_request_authorization_v2.html')

@app.route('/qr-scan-authorization')
@login_required
def qr_scan_authorization():
    """
    Page pour appareil maître : scanner QR d'un nouvel appareil
    """
    return render_template('qr_scan_authorization.html')

@app.route('/authorize-device')
@login_required
def authorize_device_page():
    """
    Page pour autoriser un appareil (code OU QR)
    """
    return render_template('authorize_device.html')


# =========================================

@app.route('/api/create-auth-session', methods=['POST'])
@login_required
def create_auth_session():
    """Créer session avec code 6 chiffres"""
    username = session.get('username')
    data = request.get_json()
    
    auth_code = data.get('auth_code')
    device_info = data.get('device_info', {})
    
    if not auth_code or len(auth_code) != 6:
        return jsonify({'success': False, 'error': 'Code invalide'}), 400
    
    # Stocker session temporaire (60s)
    import time
    import json
    
    session_id = f"auth_{username}_{int(time.time())}"
    session_data = {
        'session_id': session_id,
        'username': username,
        'auth_code': auth_code,
        'device_info': device_info,
        'status': 'pending',
        'created_at': int(time.time())
    }
    
    # Sauvegarder (fichier temporaire pour simplifier)
    session_file = f'/tmp/auth_session_{session_id}.json'
    with open(session_file, 'w') as f:
        json.dump(session_data, f)
    
    print(f"[AUTH CODE] Session créée : {session_id}, code: {auth_code}")
    
    return jsonify({'success': True, 'session_id': session_id})

@app.route('/api/authorize-with-code', methods=['POST'])
@login_required
def authorize_with_code():
    """Autoriser appareil avec code 6 chiffres"""
    username = session.get('username')
    data = request.get_json()
    
    auth_code = data.get('auth_code')
    
    if not auth_code:
        return jsonify({'success': False, 'error': 'Code manquant'}), 400
    
    # Chercher session correspondante
    import glob
    import json
    import time
    
    for session_file in glob.glob(f'/tmp/auth_session_auth_{username}_*.json'):
        try:
            with open(session_file, 'r') as f:
                session_data = json.load(f)
            
            # Check code + expiration
            if session_data['auth_code'] == auth_code:
                age = int(time.time()) - session_data['created_at']
                if age > 60:
                    return jsonify({'success': False, 'error': 'Code expiré'}), 410
                
                # Marquer comme autorisé
                session_data['status'] = 'authorized'
                with open(session_file, 'w') as f:
                    json.dump(session_data, f)
                
                print(f"[AUTH CODE] Code validated: {auth_code}")
                return jsonify({'success': True, 'message': 'Appareil autorisé'})
        
        except Exception as e:
            print(f"Erreur lecture session: {e}")
            continue
    
    return jsonify({'success': False, 'error': 'Code invalide'}), 404

@app.route('/api/check-auth-status', methods=['GET'])
def check_auth_status():
    """Vérifier statut autorisation par polling"""
    session_id = request.args.get('session_id')
    
    if not session_id:
        return jsonify({'error': 'session_id manquant'}), 400
    
    import json
    session_file = f'/tmp/auth_session_{session_id}.json'
    
    try:
        with open(session_file, 'r') as f:
            session_data = json.load(f)
        
        return jsonify({
            'status': session_data['status'],
            'session_id': session_id
        })
    except FileNotFoundError:
        return jsonify({'status': 'not_found'}), 404

# =========================================
# HOME PAGE
# =========================================
@app.route('/')
@login_required
def index():
    username = session.get('username')
    is_admin = (username == app.config['ADMIN_USERNAME'])

    # Get security level and devices
    security_mgr = get_security_manager()
    security_level = security_mgr.get_user_security_level(username)
    devices_count = len(security_mgr.get_user_devices(username))

    # Calcul du stockage réel
    storage_used_mb = 0
    storage_limit_gb = 50  # Limite fictive pour l'exemple
    try:
        # On demande au serveur de stockage la taille du dossier utilisateur
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            start_command(s, 'S', username) # 'S' pour Size/Storage (commande à implémenter côté serveur ou simuler ici)
            # Note: Si la commande 'S' n'existe pas sur le serveur, on peut lister les fichiers et sommer les tailles
            # Pour l'instant, on va simuler en listant les fichiers car on ne peut pas toucher au backend serveur
            
            # Lister fichiers pour calculer la taille
            start_command(s, 'L', username)
            list_size = struct.unpack('!I', s.recv(4))[0]
            enc_list = s.recv(list_size).decode('utf-8').split('\n') if list_size > 0 else []
            s.sendall(b'E')
            
            # Cette méthode est approximative car 'L' ne donne pas la taille.
            # Idéalement il faudrait une commande 'DU' (Disk Usage).
            # Faute de mieux sans toucher au serveur.py, on va estimer ou mettre une valeur placeholder "Réel"
            # SI on a accès au dossier storage localement (montage docker), on peut calculer directement.
            
            # Vérifions si on a accès au dossier storage monté
            user_storage_path = os.path.join(STORAGE_DIR, username)
            if os.path.exists(user_storage_path):
                total_size = 0
                for dirpath, dirnames, filenames in os.walk(user_storage_path):
                    for f in filenames:
                        fp = os.path.join(dirpath, f)
                        total_size += os.path.getsize(fp)
                storage_used_mb = total_size / (1024 * 1024)
            else:
                # Fallback si pas d'accès direct
                storage_used_mb = 0
                
    except Exception as e:
        print(f"[STORAGE] Erreur calcul stockage: {e}")
        storage_used_mb = 0

    storage_percent = (storage_used_mb / (storage_limit_gb * 1024)) * 100

    # Get last 3 user activities
    logger = get_activity_logger()
    recent_activities = logger.get_user_logs(username, limit=3)

    return render_template('index.html',
                         username=username,
                         is_admin=is_admin,
                         security_level=security_level,
                         devices_count=devices_count,
                         storage_used_mb=round(storage_used_mb, 2),
                         storage_percent=round(storage_percent, 1),
                         storage_limit_gb=storage_limit_gb,
                         recent_activities=recent_activities)

# =========================================
# FILE UPLOAD
# =========================================
@app.route('/upload', methods=['POST'])
@login_required
def upload_files():
    username = session.get('username')
    is_admin = (username == app.config['ADMIN_USERNAME'])

    # Get security level for template
    security_mgr = get_security_manager()
    security_level = security_mgr.get_user_security_level(username)
    devices_count = len(security_mgr.get_user_devices(username))

    # Calcul du stockage pour le template
    storage_used_mb = 0
    storage_limit_gb = 10
    storage_dir_user = os.path.join(STORAGE_DIR, username)
    if os.path.exists(storage_dir_user):
        for root, dirs, files in os.walk(storage_dir_user):
            for f in files:
                fpath = os.path.join(root, f)
                if os.path.isfile(fpath):
                    storage_used_mb += os.path.getsize(fpath) / (1024 * 1024)
    storage_percent = (storage_used_mb / (storage_limit_gb * 1024)) * 100

    # Activités récentes pour le template
    logger = get_activity_logger()
    recent_activities = logger.get_user_logs(username, limit=3)

    files = request.files.getlist('files_to_upload')
    if not files or files[0].filename == '':
        return render_template('index.html', username=username, is_admin=is_admin,
            security_level=security_level, devices_count=devices_count,
            storage_used_mb=round(storage_used_mb, 2),
            storage_percent=round(storage_percent, 1),
            storage_limit_gb=storage_limit_gb,
            recent_activities=recent_activities,
            message="Erreur : Aucun fichier/dossier sélectionné.")

    count = 0

    # Get current path from form data (for uploads from restore page)
    current_path = request.form.get('current_path', '').strip()
    print(f"[UPLOAD X25519] Current path: '{current_path}'")


    # Check user's public key
    user_pubkey_path = os.path.join(USER_KEYS_DIR, username, 'public_key.pem')
    print(f"[UPLOAD X25519] Utilisateur : {username}")
    print(f"[UPLOAD X25519] Clé publique : {user_pubkey_path}")

    if not os.path.exists(user_pubkey_path):
        print(f"[UPLOAD X25519] Public key not found")
        
        # En mode standard, générer les clés automatiquement
        if security_level == SECURITY_LEVEL_STANDARD:
            print(f"[UPLOAD X25519] Tentative de génération automatique des clés...")
            if _generate_basic_keys_for_user(username):
                # Check again after generation
                if not os.path.exists(user_pubkey_path):
                    return render_template('index.html', username=username, is_admin=is_admin,
                        security_level=security_level, devices_count=devices_count,
                        storage_used_mb=round(storage_used_mb, 2),
                        storage_percent=round(storage_percent, 1),
                        storage_limit_gb=storage_limit_gb,
                        recent_activities=recent_activities,
                        message=f"Erreur : Impossible de générer les clés de chiffrement")
            else:
                return render_template('index.html', username=username, is_admin=is_admin,
                    security_level=security_level, devices_count=devices_count,
                    storage_used_mb=round(storage_used_mb, 2),
                    storage_percent=round(storage_percent, 1),
                    storage_limit_gb=storage_limit_gb,
                    recent_activities=recent_activities,
                    message=f"Erreur : Impossible de générer les clés de chiffrement")
        else:
            # Mode maximum : clés zero-knowledge requises
            return render_template('index.html', username=username, is_admin=is_admin,
                security_level=security_level, devices_count=devices_count,
                storage_used_mb=round(storage_used_mb, 2),
                storage_percent=round(storage_percent, 1),
                storage_limit_gb=storage_limit_gb,
                recent_activities=recent_activities,
                message=f"Erreur : Clés zero-knowledge requises. Configurez vos clés depuis les paramètres.")
    
    # VALIDATION: Check that the key is the right type
    # NOTE: En mode maximum, on ACCEPTE les clés EC (P-256) car Web Crypto API
    # ne supporte pas X25519. Le JavaScript génère des clés ECDH P-256.
    if security_level == SECURITY_LEVEL_MAXIMUM:
        import sys
        sys.path.append(os.path.dirname(os.path.dirname(__file__)))
        from lib.auth.device_manager import get_user_key_type
        
        key_type = get_user_key_type(username)
        print(f"[UPLOAD] Type de clé détecté : {key_type}")
        
        # En mode maximum, on accepte EC (P-256) car c'est ce que génère Web Crypto
        if key_type not in ['EC', 'X25519']:
            print(f"[UPLOAD] Invalid key: {key_type}")
            return render_template('index.html', username=username, is_admin=is_admin,
                security_level=security_level, devices_count=devices_count,
                storage_used_mb=round(storage_used_mb, 2),
                storage_percent=round(storage_percent, 1),
                storage_limit_gb=storage_limit_gb,
                recent_activities=recent_activities,
                message=f"WARNING: Invalid key type. Please reconnect.")


    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

            for file in files:
                temp_orig_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(file.filename))
                file.save(temp_orig_path)

                # Chiffrement avec X25519
                print(f"[UPLOAD X25519] Chiffrement de {file.filename}...")
                fichier_enc_path, cle_aes_enc_path = chiffrer_fichier_complet(
                    temp_orig_path,
                    user_pubkey_path,
                    app.config['UPLOAD_FOLDER']
                )
                print(f"[UPLOAD X25519] Résultat : enc={fichier_enc_path}, key={cle_aes_enc_path}")

                if fichier_enc_path and cle_aes_enc_path:
                    print(f"[UPLOAD X25519] Encryption successful, sending to server...")

                    # Construct full path including current_path if provided
                    if current_path:
                        full_file_path = f"{current_path}/{file.filename}"
                    else:
                        full_file_path = file.filename

                    print(f"[UPLOAD X25519] Full path: {full_file_path}")

                    # Upload fichier chiffré
                    start_command(s, 'F', username)
                    enc_rel_path = full_file_path + ".enc"
                    send_prefixed_string(s, enc_rel_path)
                    filesize = os.path.getsize(fichier_enc_path)
                    s.sendall(struct.pack('!Q', filesize))
                    with open(fichier_enc_path, 'rb') as f_enc:
                        while chunk := f_enc.read(4096):
                            s.sendall(chunk)

                    # Upload clé AES chiffrée
                    print(f"[UPLOAD X25519] Upload de la clé AES chiffrée...")
                    start_command(s, 'F', username)
                    key_rel_path = full_file_path + ".key"
                    send_prefixed_string(s, key_rel_path)
                    keysize = os.path.getsize(cle_aes_enc_path)
                    s.sendall(struct.pack('!Q', keysize))
                    with open(cle_aes_enc_path, 'rb') as f_key:
                        while chunk := f_key.read(4096):
                            s.sendall(chunk)
                    print(f"[UPLOAD X25519] Key uploaded: {key_rel_path}")

                    count += 1
                    print(f"[UPLOAD X25519] Complete file uploaded (enc + key)")

                    # Logger l'upload réussi avec le chemin complet
                    logger = get_activity_logger()
                    logger.log_activity(username, 'FILE_UPLOAD', request.remote_addr,
                                      'SUCCESS', f'Fichier: {full_file_path}',
                                      user_agent=request.headers.get('User-Agent', ''))

                    # Nettoyage
                    os.remove(fichier_enc_path)
                    os.remove(cle_aes_enc_path)
                else:
                    print(f"[UPLOAD X25519] Encryption failed for {file.filename}")

                os.remove(temp_orig_path)

            s.sendall(b'E')

        # If AJAX request (from restore.html), return JSON
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.form.get('current_path') is not None:
            return jsonify({'success': True, 'message': f'{count}/{len(files)} fichier(s) uploadé(s) avec succès'}), 200

        msg = f"Succès : {count}/{len(files)} fichier(s) envoyé(s) de manière sécurisée."
        return render_template('index.html', username=username, is_admin=is_admin,
            security_level=security_level, devices_count=devices_count,
            storage_used_mb=round(storage_used_mb, 2),
            storage_percent=round(storage_percent, 1),
            storage_limit_gb=storage_limit_gb,
            recent_activities=recent_activities,
            message=msg)
    except Exception as e:
        # If AJAX request, return JSON
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.form.get('current_path') is not None:
            return jsonify({'success': False, 'message': str(e)}), 500

        return render_template('index.html', username=username, is_admin=is_admin,
            security_level=security_level, devices_count=devices_count,
            storage_used_mb=round(storage_used_mb, 2),
            storage_percent=round(storage_percent, 1),
            storage_limit_gb=storage_limit_gb,
            recent_activities=recent_activities,
            message=f"Erreur Critique : {e}")

# =========================================
# FILE RESTORATION
# =========================================
@app.route('/restore')
@app.route('/restore/<path:current_path>')
@login_required
def restore_page(current_path=''):
    username = session.get('username')
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            start_command(s, 'L', username)
            list_size = struct.unpack('!I', s.recv(4))[0]
            enc_list = s.recv(list_size).decode('utf-8').split('\n') if list_size > 0 else []

        # Exclure les éléments dans .versions (les versions ne doivent pas figurer dans Restauration)
        base_enc_list = [f for f in enc_list if f.endswith('.enc') and '.versions' not in f]
        # Normaliser le séparateur pour les URLs (éviter 404 avec '\\' sous Windows)
        all_files = [f.replace('.enc', '').replace('\\', '/') for f in base_enc_list]

        # Filtrer les fichiers selon le chemin courant
        if current_path:
            # Filtrer les fichiers qui commencent par le chemin courant
            filtered_files = [f for f in all_files if f.startswith(current_path + '/')]
            # Retirer le préfixe du chemin courant
            relative_files = [f[len(current_path)+1:] for f in filtered_files]
        else:
            relative_files = all_files

        # Séparer les dossiers et fichiers du niveau courant
        folders = set()
        files = []
        file_sizes = {}  # Dictionnaire pour stocker les tailles des fichiers

        for item in relative_files:
            if '/' in item:
                # C'est dans un sous-dossier, extraire le nom du dossier
                folder_name = item.split('/')[0]
                folders.add(folder_name)
            else:
                # C'est un fichier à ce niveau
                files.append(item)

                # Calculer la taille du fichier
                try:
                    # Construire le chemin complet du fichier chiffré
                    if current_path:
                        full_path = os.path.join(current_path, item)
                    else:
                        full_path = item

                    enc_file_path = os.path.join(STORAGE_DIR, username, full_path + '.enc')

                    if os.path.exists(enc_file_path):
                        size_bytes = os.path.getsize(enc_file_path)
                        file_sizes[item] = size_bytes
                    else:
                        file_sizes[item] = 0
                except Exception as e:
                    print(f"Erreur calcul taille pour {item}: {e}")
                    file_sizes[item] = 0

        folder_list = sorted(list(folders))
        file_list = sorted(files)

        # Formater les tailles de fichiers
        def format_size(size_bytes):
            """Convertir les bytes en format lisible (KB, MB, GB)"""
            if size_bytes < 1024:
                return f"{size_bytes} B"
            elif size_bytes < 1024 * 1024:
                return f"{size_bytes / 1024:.1f} KB"
            elif size_bytes < 1024 * 1024 * 1024:
                return f"{size_bytes / (1024 * 1024):.1f} MB"
            else:
                return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"

        # Create file list with their information
        files_with_sizes = []
        for file in file_list:
            size_bytes = file_sizes.get(file, 0)
            files_with_sizes.append({
                'name': file,
                'size': format_size(size_bytes),
                'size_bytes': size_bytes,
                'modified': None  # Peut être ajouté plus tard si besoin
            })

        # Construire le breadcrumb
        breadcrumb = []
        if current_path:
            parts = current_path.split('/')
            path_so_far = ''
            for part in parts:
                path_so_far = path_so_far + '/' + part if path_so_far else part
                breadcrumb.append({'name': part, 'path': path_so_far})

        # Parent path (pour le bouton retour)
        parent_path = '/'.join(current_path.split('/')[:-1]) if current_path and '/' in current_path else '' if current_path else None

        is_admin = (username == app.config['ADMIN_USERNAME'])
        message = request.args.get('message')

        # Get user's latest upload logs
        logger = get_activity_logger()
        all_logs = logger.get_user_logs(username, limit=50)
        # Filtrer uniquement les logs d'upload réussis
        upload_logs = [log for log in all_logs if log.get('action') == 'FILE_UPLOAD' and log.get('status') == 'SUCCESS']
        # Garder uniquement les 10 derniers
        recent_uploads = upload_logs[:10]

        return render_template('restore.html',
                             files=file_list,
                             folders=folder_list,
                             files_with_sizes=files_with_sizes,
                             file_sizes=file_sizes,
                             current_path=current_path,
                             breadcrumb=breadcrumb,
                             parent_path=parent_path,
                             is_admin=is_admin,
                             username=username,
                             message=message,
                             recent_uploads=recent_uploads,
                             get_security_manager=get_security_manager)
    except Exception as e:
        return f"<h1>Erreur de connexion</h1><p>{e}</p>"

# =========================================
# API: ALL FILES (for global search)
# =========================================
@app.route('/api/all_files')
@login_required
def api_all_files():
    """Retourne tous les fichiers de l'utilisateur pour la recherche globale"""
    username = session.get('username')
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            start_command(s, 'L', username)
            list_size = struct.unpack('!I', s.recv(4))[0]
            enc_list = s.recv(list_size).decode('utf-8').split('\n') if list_size > 0 else []

        # Exclure les éléments dans .versions
        base_enc_list = [f for f in enc_list if f.endswith('.enc') and '.versions' not in f]
        # Normaliser le séparateur et retirer l'extension .enc
        all_files = [f.replace('.enc', '').replace('\\', '/') for f in base_enc_list]

        return jsonify({'files': all_files})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =========================================
# API: CURRENT DIRECTORY LISTING (for dynamic refresh)
# =========================================
@app.route('/api/directory_listing')
@app.route('/api/directory_listing/<path:current_path>')
@login_required
def api_directory_listing(current_path=''):
    """Retourne le listing du répertoire courant pour le rafraîchissement dynamique"""
    username = session.get('username')
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            start_command(s, 'L', username)
            list_size = struct.unpack('!I', s.recv(4))[0]
            enc_list = s.recv(list_size).decode('utf-8').split('\n') if list_size > 0 else []

        # Exclure les éléments dans .versions
        base_enc_list = [f for f in enc_list if f.endswith('.enc') and '.versions' not in f]
        # Normaliser le séparateur
        all_files = [f.replace('.enc', '').replace('\\', '/') for f in base_enc_list]

        # Filtrer les fichiers selon le chemin courant
        if current_path:
            filtered_files = [f for f in all_files if f.startswith(current_path + '/')]
            relative_files = [f[len(current_path)+1:] for f in filtered_files]
        else:
            relative_files = all_files

        # Séparer les dossiers et fichiers du niveau courant
        folders = set()
        files = []
        file_sizes = {}

        for item in relative_files:
            if '/' in item:
                folder_name = item.split('/')[0]
                folders.add(folder_name)
            else:
                files.append(item)

                # Calculer la taille du fichier
                try:
                    if current_path:
                        full_path = os.path.join(current_path, item)
                    else:
                        full_path = item

                    enc_file_path = os.path.join(STORAGE_DIR, username, full_path + '.enc')

                    if os.path.exists(enc_file_path):
                        size_bytes = os.path.getsize(enc_file_path)
                        file_sizes[item] = size_bytes
                    else:
                        file_sizes[item] = 0
                except Exception as e:
                    print(f"Erreur calcul taille pour {item}: {e}")
                    file_sizes[item] = 0

        folder_list = sorted(list(folders))
        file_list = sorted(files)

        # Formater les tailles de fichiers
        def format_size(size_bytes):
            if size_bytes < 1024:
                return f"{size_bytes} B"
            elif size_bytes < 1024 * 1024:
                return f"{size_bytes / 1024:.1f} KB"
            elif size_bytes < 1024 * 1024 * 1024:
                return f"{size_bytes / (1024 * 1024):.1f} MB"
            else:
                return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"

        # Create file list with their information
        files_with_sizes = []
        for file in file_list:
            size_bytes = file_sizes.get(file, 0)
            files_with_sizes.append({
                'name': file,
                'size': format_size(size_bytes),
                'size_bytes': size_bytes
            })

        # Get latest upload logs
        logger = get_activity_logger()
        all_logs = logger.get_user_logs(username, limit=50)
        upload_logs = [log for log in all_logs if log.get('action') == 'FILE_UPLOAD' and log.get('status') == 'SUCCESS']
        recent_uploads = upload_logs[:10]

        return jsonify({
            'success': True,
            'folders': folder_list,
            'files': files_with_sizes,
            'recent_uploads': recent_uploads
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# =========================================
# VERSIONS: LIST, DOWNLOAD, RESTORATION
# =========================================
@app.route('/versions')
@app.route('/versions/<path:current_path>')
@login_required
def versions_page(current_path=''):
    username = session.get('username')
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            # Lister fichiers
            start_command(s, 'L', username)
            list_size = struct.unpack('!I', s.recv(4))[0]
            enc_list = s.recv(list_size).decode('utf-8').split('\n') if list_size > 0 else []
            # Ne garder que les fichiers courants (pas les fichiers dans .versions)
            base_enc_list = [f for f in enc_list if f.endswith('.enc') and '.versions' not in f]
            all_files = [f.replace('.enc', '').replace('\\', '/') for f in base_enc_list]

            # Filtrer les fichiers selon le chemin courant
            if current_path:
                # Filtrer les fichiers qui commencent par le chemin courant
                filtered_files = [f for f in all_files if f.startswith(current_path + '/')]
                # Retirer le préfixe du chemin courant
                relative_files = [f[len(current_path)+1:] for f in filtered_files]
            else:
                relative_files = all_files

            # Séparer les dossiers et fichiers du niveau courant
            folders = set()
            files = []
            for item in relative_files:
                if '/' in item:
                    # C'est dans un sous-dossier, extraire le nom du dossier
                    folder_name = item.split('/')[0]
                    folders.add(folder_name)
                else:
                    # C'est un fichier à ce niveau
                    files.append(item)

            folder_list = sorted(list(folders))
            file_list = sorted(files)

            # Get versions for each file at current level
            versions_map = {}
            for file in file_list:
                full_path = (current_path + '/' + file if current_path else file)
                enc_path = (full_path + ".enc").replace('/', os.sep)

                start_command(s, 'V', username)
                send_prefixed_string(s, enc_path)
                vlen = struct.unpack('!I', s.recv(4))[0]
                versions = s.recv(vlen).decode('utf-8').split('\n') if vlen > 0 else []
                # Utiliser le nom de fichier relatif comme clé
                versions_map[file] = versions
            s.sendall(b'E')

            # Construire le breadcrumb
            breadcrumb = []
            if current_path:
                parts = current_path.split('/')
                path_so_far = ''
                for part in parts:
                    path_so_far = path_so_far + '/' + part if path_so_far else part
                    breadcrumb.append({'name': part, 'path': path_so_far})

            # Parent path (pour le bouton retour)
            parent_path = '/'.join(current_path.split('/')[:-1]) if current_path and '/' in current_path else '' if current_path else None

        is_admin = (username == app.config['ADMIN_USERNAME'])
        message = request.args.get('message')
        return render_template('versions.html',
                             files=file_list,
                             folders=folder_list,
                             current_path=current_path,
                             breadcrumb=breadcrumb,
                             parent_path=parent_path,
                             versions_map=versions_map,
                             is_admin=is_admin,
                             username=username,
                             message=message)
    except Exception as e:
        return f"<h1>Erreur</h1><p>{e}</p>"


@app.route('/download_version/<path:filepath>/<version>')
@login_required
def download_version(filepath, version):
    username = session.get('username')

    # Check access based on security level
    can_access, access_message, device_fp = check_security_access(username)
    if not can_access:
        return render_template('access_denied.html',
                             message=access_message,
                             username=username,
                             security_level=get_security_manager().get_user_security_level(username))

    # Check security mode
    security_mgr = get_security_manager()
    security_level = security_mgr.get_user_security_level(username)

    # Mode maximum : déchiffrement côté client
    if security_level == SECURITY_LEVEL_MAXIMUM:
        # Rediriger vers la page de déchiffrement client avec les paramètres de version
        return redirect(url_for('client_decrypt_version', filepath=filepath, version=version))

    # Mode standard : déchiffrement côté serveur
    user_privkey_path = os.path.join(USER_KEYS_DIR, username, 'private_key.pem')
    if not os.path.exists(user_privkey_path):
        return redirect(url_for('setup_keys'))

    # Construire les chemins des fichiers de version
    if not filepath.endswith('.enc'):
        base_filepath = filepath
    else:
        base_filepath = filepath.replace('.enc', '')

    # Chemins dans .versions/
    enc_version_path = f".versions/{base_filepath}.enc/{version}.enc"
    key_version_path = f".versions/{base_filepath}.key/{version}.key"

    try:
        download_dir = os.path.join(app.root_path, app.config['DOWNLOAD_FOLDER'])
        os.makedirs(download_dir, exist_ok=True)

        # Télécharger le fichier .enc de la version
        temp_enc_path = os.path.join(download_dir, f"{os.path.basename(base_filepath)}.v{version}.enc")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            start_command(s, 'G', username)
            send_prefixed_string(s, enc_version_path.replace('/', os.sep))
            filesize = struct.unpack('!Q', s.recv(8))[0]

            if filesize == 0:
                return "<h1>Erreur</h1><p>Version .enc introuvable sur le serveur.</p>"

            with open(temp_enc_path, 'wb') as f:
                rec, total = 0, filesize
                while rec < total:
                    chunk = s.recv(4096)
                    f.write(chunk)
                    rec += len(chunk)

        # Télécharger le fichier .key de la version
        temp_key_path = os.path.join(download_dir, f"{os.path.basename(base_filepath)}.v{version}.key")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            start_command(s, 'G', username)
            send_prefixed_string(s, key_version_path.replace('/', os.sep))
            keysize = struct.unpack('!Q', s.recv(8))[0]

            if keysize == 0:
                os.remove(temp_enc_path)
                return "<h1>Erreur</h1><p>Version .key introuvable sur le serveur. La version n'a peut-être pas été sauvegardée correctement.</p>"

            with open(temp_key_path, 'wb') as f:
                rec, total = 0, keysize
                while rec < total:
                    chunk = s.recv(4096)
                    f.write(chunk)
                    rec += len(chunk)

        # Déchiffrer avec X25519
        temp_dec_path = dechiffrer_fichier_complet(
            temp_enc_path,
            temp_key_path,
            user_privkey_path,
            download_dir
        )

        from flask import send_file

        if temp_dec_path:
            # Déchiffrement réussi
            print(f"[DOWNLOAD_VERSION] Version {version} de {filepath} déchiffrée avec succès")

            # Logger le téléchargement
            logger = get_activity_logger()
            logger.log_activity(username, 'VERSION_DOWNLOAD', request.remote_addr,
                              'SUCCESS', f'Fichier: {filepath}, Version: {version}',
                              user_agent=request.headers.get('User-Agent', ''))

            response = send_file(temp_dec_path, as_attachment=True, download_name=f"{os.path.basename(base_filepath)}_v{version}")

            @response.call_on_close
            def cleanup():
                try:
                    os.remove(temp_enc_path)
                    os.remove(temp_key_path)
                    os.remove(temp_dec_path)
                except Exception as e:
                    print(f"Erreur nettoyage version {filepath}@{version}: {e}")

            return response
        else:
            # Déchiffrement échoué
            print(f"[DOWNLOAD_VERSION] Échec du déchiffrement de la version {version} de {filepath}")
            os.remove(temp_enc_path)
            os.remove(temp_key_path)
            return "<h1>Erreur</h1><p>Déchiffrement de la version échoué. Vérifiez votre clé privée.</p>"

    except Exception as e:
        print(f"[DOWNLOAD_VERSION] Erreur: {e}")
        import traceback
        traceback.print_exc()
        return f"<h1>Erreur</h1><p>{e}</p>"


@app.route('/restore_version', methods=['POST'])
@login_required
def restore_version():
    username = session.get('username')
    filepath = request.form.get('filepath')
    version = request.form.get('version')
    current_path = request.form.get('current_path', '')

    print(f"[RESTORE_VERSION] filepath: {filepath}, version: {version}, current_path: {current_path}")

    if not filepath or not version:
        if current_path:
            return redirect(url_for('versions_page', current_path=current_path) + '?message=Paramètres manquants')
        return redirect(url_for('versions_page') + '?message=Paramètres manquants')

    # Ajouter .enc seulement si nécessaire
    if not filepath.endswith('.enc'):
        enc_filepath = filepath + ".enc"
    else:
        enc_filepath = filepath

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            start_command(s, 'R', username)
            # Convertir chemin URL -> OS pour le serveur
            send_prefixed_string(s, enc_filepath.replace('/', os.sep))
            send_prefixed_string(s, version)

            # Lire ACK
            ack_len = struct.unpack('!I', s.recv(4))[0]
            ack_msg = s.recv(ack_len).decode('utf-8') if ack_len > 0 else ''
            s.sendall(b'E')

        print(f"[RESTORE_VERSION] Réponse serveur: {ack_msg}")

        msg = 'Version restaurée avec succès.' if ack_msg == 'OK' else ack_msg

        # Rester sur la même page (current_path)
        if current_path:
            return redirect(url_for('versions_page', current_path=current_path) + f'?message={msg}')
        return redirect(url_for('versions_page') + f'?message={msg}')

    except Exception as e:
        print(f"[RESTORE_VERSION] Erreur: {e}")
        import traceback
        traceback.print_exc()
        if current_path:
            return redirect(url_for('versions_page', current_path=current_path) + f'?message=Erreur: {e}')
        return redirect(url_for('versions_page') + f'?message=Erreur: {e}')

# =========================================
# DELETE (admin only)
# =========================================
@app.route('/delete_version', methods=['POST'])
@login_required
def delete_version():
    username = session.get('username')
    if username != app.config['ADMIN_USERNAME']:
        return redirect(url_for('versions_page', message='Action réservée à l\'admin.'))
    filepath = request.form.get('filepath')
    version = request.form.get('version')
    current_path = request.form.get('current_path', '')
    if not filepath or not version:
        return redirect(url_for('versions_page', current_path=current_path, message='Paramètres manquants.'))
    enc_filepath = (filepath + ".enc").replace('/', os.sep)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            start_command(s, 'X', username)
            send_prefixed_string(s, enc_filepath)
            send_prefixed_string(s, version)
            try:
                ack_len = struct.unpack('!I', s.recv(4))[0]
                ack_msg = s.recv(ack_len).decode('utf-8') if ack_len > 0 else ''
            except Exception:
                ack_msg = ''
            s.sendall(b'E')
        msg = 'Version supprimée.' if ack_msg == 'OK' else (ack_msg or 'Suppression effectuée.')
        # Rediriger vers le dossier courant
        parent_path = '/'.join(filepath.split('/')[:-1]) if '/' in filepath else ''
        return redirect(url_for('versions_page', current_path=parent_path, message=msg))
    except Exception as e:
        return redirect(url_for('versions_page', current_path=current_path, message=f'Erreur: {e}'))

@app.route('/delete_file', methods=['POST'])
@login_required
def delete_file_route():
    username = session.get('username')
    filepath = request.form.get('filepath')
    current_path = request.form.get('current_path', '')

    if not filepath:
        if current_path:
            return redirect(url_for('restore_page', current_path=current_path) + f'?message=Paramètres manquants')
        return redirect(url_for('restore_page') + '?message=Paramètres manquants')

    # Ajouter .enc seulement si le fichier ne l'a pas déjà
    if not filepath.endswith('.enc'):
        enc_filepath = (filepath + ".enc").replace('/', os.sep)
    else:
        enc_filepath = filepath.replace('/', os.sep)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            start_command(s, 'D', username)
            send_prefixed_string(s, enc_filepath)

            ack_len = struct.unpack('!I', s.recv(4))[0]
            ack_msg = s.recv(ack_len).decode('utf-8') if ack_len > 0 else ''
            s.sendall(b'E')

        msg = 'Fichier supprimé.' if ack_msg == 'OK' else ack_msg

        # Rester sur la même page
        if current_path:
            return redirect(url_for('restore_page', current_path=current_path) + f'?message={msg}')
        return redirect(url_for('restore_page') + f'?message={msg}')

    except Exception as e:
        if current_path:
            return redirect(url_for('restore_page', current_path=current_path) + f'?message=Erreur: {e}')
        return redirect(url_for('restore_page') + f'?message=Erreur: {e}')

@app.route('/delete_folder', methods=['POST'])
@login_required
def delete_folder_route():
    username = session.get('username')
    folderpath = request.form.get('folderpath')
    current_path = request.form.get('current_path', '')

    if not folderpath:
        if current_path:
            return redirect(url_for('restore_page', current_path=current_path) + '?message=Paramètres manquants')
        return redirect(url_for('restore_page') + '?message=Paramètres manquants')

    # Ne pas ajouter .enc pour un dossier
    folder_path_normalized = folderpath.replace('/', os.sep)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            start_command(s, 'M', username)
            send_prefixed_string(s, folder_path_normalized)

            ack_len = struct.unpack('!I', s.recv(4))[0]
            ack_msg = s.recv(ack_len).decode('utf-8') if ack_len > 0 else ''
            s.sendall(b'E')

        msg = 'Dossier supprimé.' if ack_msg == 'OK' else ack_msg

        # Rester sur la même page
        if current_path:
            return redirect(url_for('restore_page', current_path=current_path) + f'?message={msg}')
        return redirect(url_for('restore_page') + f'?message={msg}')

    except Exception as e:
        if current_path:
            return redirect(url_for('restore_page', current_path=current_path) + f'?message=Erreur: {e}')
        return redirect(url_for('restore_page') + f'?message=Erreur: {e}')

# =========================================
# DOWNLOAD
# =========================================
@app.route('/download/<path:filepath>')
@login_required
def download_file(filepath):
    username = session.get('username')
    is_admin_user = (username == app.config['ADMIN_USERNAME'])

    # Check access based on security level
    can_access, access_message, device_fp = check_security_access(username)

    if not can_access:
        return render_template('access_denied.html',
                             message=access_message,
                             username=username,
                             security_level=get_security_manager().get_user_security_level(username))

    # Déterminer le propriétaire du fichier en regardant le chemin de stockage
    # Les fichiers sont stockés dans storage/<username>/<filepath>
    # filepath commence par le username du propriétaire pour l'admin
    if is_admin_user and '/' in filepath:
        # L'admin browse les fichiers d'un autre user
        file_owner = filepath.split('/')[0]
        # Check if this is not one of their own files
        if file_owner != username:
            # L'admin ne peut pas télécharger les fichiers des autres users
            # (il n'a pas leurs clés privées)
            return """
                <script>
                    alert("❌ Impossible de télécharger ce fichier\\n\\nVous ne possédez pas la clé privée de cet utilisateur.\\n\\nEn tant qu'administrateur, vous pouvez uniquement supprimer les fichiers des utilisateurs, pas les télécharger.");
                    window.history.back();
                </script>
            """

    # Check security mode
    security_mgr = get_security_manager()
    security_level = security_mgr.get_user_security_level(username)

    # Mode maximum : déchiffrement côté client
    if security_level == SECURITY_LEVEL_MAXIMUM:
        # Rediriger vers la page de déchiffrement client
        return redirect(url_for('client_decrypt_file', filepath=filepath))

    # Mode standard : déchiffrement côté serveur (besoin de la clé PEM locale)
    user_privkey_path = os.path.join(USER_KEYS_DIR, username, 'private_key.pem')
    if not os.path.exists(user_privkey_path):
        # L'utilisateur n'a pas de clé privée (mode ancien ou premier setup)
        return """
            <script>
                alert("❌ Clé privée introuvable\\n\\nVeuillez configurer vos clés de chiffrement.");
                window.location.href = "/setup-keys";
            </script>
        """

    # Ajouter .enc seulement si le fichier ne l'a pas déjà
    if not filepath.endswith('.enc'):
        enc_filepath = filepath + ".enc"
        key_filepath = filepath + ".key"
    else:
        enc_filepath = filepath
        key_filepath = filepath.replace('.enc', '.key')

    try:
        download_dir = os.path.join(app.root_path, app.config['DOWNLOAD_FOLDER'])
        os.makedirs(download_dir, exist_ok=True)

        # Télécharger fichier chiffré (.enc)
        temp_enc_path = os.path.join(download_dir, os.path.basename(enc_filepath))
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            start_command(s, 'G', username)
            send_prefixed_string(s, enc_filepath.replace('/', os.sep))
            filesize = struct.unpack('!Q', s.recv(8))[0]

            if filesize == 0:
                return "<h1>Erreur</h1><p>Fichier .enc non trouvé sur le serveur.</p>"

            with open(temp_enc_path, 'wb') as f:
                rec, total = 0, filesize
                while rec < total:
                    chunk = s.recv(4096)
                    f.write(chunk)
                    rec += len(chunk)

        # Télécharger clé AES chiffrée (.key)
        temp_key_path = os.path.join(download_dir, os.path.basename(key_filepath))
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            start_command(s, 'G', username)
            send_prefixed_string(s, key_filepath.replace('/', os.sep))
            keysize = struct.unpack('!Q', s.recv(8))[0]

            if keysize == 0:
                # Fallback : essayer avec l'ancien système
                os.remove(temp_enc_path)
                return "<h1>Erreur</h1><p>Fichier .key non trouvé. Fichier peut-être chiffré avec l'ancien système.</p>"

            with open(temp_key_path, 'wb') as f:
                rec, total = 0, keysize
                while rec < total:
                    chunk = s.recv(4096)
                    f.write(chunk)
                    rec += len(chunk)

        # Déchiffrer avec X25519
        temp_dec_path = dechiffrer_fichier_complet(
            temp_enc_path,
            temp_key_path,
            user_privkey_path,
            download_dir
        )

        from flask import send_file

        if temp_dec_path:
            # Déchiffrement réussi
            # Logger le téléchargement réussi
            logger = get_activity_logger()
            logger.log_activity(username, 'FILE_DOWNLOAD', request.remote_addr,
                              'SUCCESS', f'Fichier: {filepath}',
                              user_agent=request.headers.get('User-Agent', ''))

            response = send_file(temp_dec_path, as_attachment=True, download_name=os.path.basename(filepath))

            @response.call_on_close
            def cleanup():
                try:
                    os.remove(temp_enc_path)
                    os.remove(temp_key_path)
                    os.remove(temp_dec_path)
                except Exception as e:
                    print(f"Erreur nettoyage {filepath}: {e}")

            return response
        else:
            # Déchiffrement échoué
            os.remove(temp_enc_path)
            os.remove(temp_key_path)
            return "<h1>Erreur</h1><p>Déchiffrement échoué. Vérifiez votre clé privée.</p>"
    except Exception as e:
        print(f"[DOWNLOAD] Erreur: {e}")
        import traceback
        traceback.print_exc()
        return f"<h1>Erreur</h1><p>{e}</p>"

# =========================================
# GLOBAL SEARCH API
# =========================================
@app.route('/api/search')
@login_required
def api_search():
    """Recherche globale dans tous les fichiers de l'utilisateur"""
    query = request.args.get('q', '').lower().strip()
    username = session.get('username')

    if not query or len(query) < 2:
        return jsonify([])

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))

            # Lister TOUS les fichiers
            start_command(s, 'L', username)
            list_size = struct.unpack('!I', s.recv(4))[0]
            enc_list = s.recv(list_size).decode('utf-8').split('\n') if list_size > 0 else []

            # Filtrer les fichiers .enc (pas dans .versions)
            base_enc_list = [f for f in enc_list if f.endswith('.enc') and '.versions' not in f]
            all_files = [f.replace('.enc', '').replace('\\', '/') for f in base_enc_list]

            s.sendall(b'E')

        # Recherche: fichiers qui contiennent le terme
        results = []
        for filepath in all_files:
            filename = filepath.split('/')[-1]  # Nom du fichier
            if query in filename.lower() or query in filepath.lower():
                # Extraire le dossier parent
                if '/' in filepath:
                    folder_path = '/'.join(filepath.split('/')[:-1])
                    results.append({
                        'filename': filename,
                        'fullpath': filepath,
                        'folder': folder_path,
                        'is_in_subfolder': True
                    })
                else:
                    results.append({
                        'filename': filename,
                        'fullpath': filepath,
                        'folder': '',
                        'is_in_subfolder': False
                    })

        # Limiter à 20 résultats
        return jsonify(results[:20])

    except Exception as e:
        print(f"[SEARCH] Erreur: {e}")
        return jsonify({'error': str(e)}), 500

# =========================================
# LDAP ADMINISTRATION
# =========================================
def is_admin():
    """Vérifie si l'utilisateur connecté est admin."""
    return session.get('username') == app.config['ADMIN_USERNAME']

# =========================================
# SECURITY HELPERS
# =========================================
def get_device_fingerprint():
    """
    Génère une empreinte d'appareil basée sur les headers HTTP
    Cette empreinte côté serveur est complémentaire au fingerprinting JS côté client
    """
    user_agent = request.headers.get('User-Agent', '')
    accept_language = request.headers.get('Accept-Language', '')

    # On utilise le fingerprint passé en paramètre si disponible
    # Sinon on génère une empreinte basique côté serveur
    device_fp = request.form.get('device_fingerprint') or request.args.get('device_fingerprint')

    if device_fp:
        return device_fp

    # Fallback: générer une empreinte basique côté serveur
    import hashlib
    fingerprint_data = f"{user_agent}|{accept_language}"
    return hashlib.sha256(fingerprint_data.encode()).hexdigest()

def check_security_access(username):
    """
    Vérifie si l'utilisateur peut accéder aux fichiers depuis cet appareil

    Returns:
        Tuple (can_access: bool, message: str, device_fingerprint: str)
    """
    security_mgr = get_security_manager()
    device_fp = get_device_fingerprint()

    can_access, message = security_mgr.can_access_files(username, device_fp)

    return can_access, message, device_fp

@app.route('/admin/users', methods=['GET'])
@login_required
def admin_users():
    """Page d'administration des utilisateurs LDAP."""
    if not is_admin():
        return "Accès refusé - Admin uniquement", 403

    # Get LDAP user list
    users = []
    try:
        host = app.config['LDAP_HOST']
        port = app.config['LDAP_PORT']
        use_ssl = app.config['LDAP_USE_SSL']
        base_dn = app.config['LDAP_BASE_DN']
        user_dn = app.config['LDAP_USER_DN']
        bind_dn = app.config['LDAP_BIND_USER_DN']
        bind_pwd = app.config['LDAP_BIND_USER_PASSWORD']

        server = Server(host, port=port, use_ssl=use_ssl, get_info=ALL)
        conn = Connection(server, bind_dn, bind_pwd, auto_bind=True)

        search_base = f"{user_dn},{base_dn}"
        conn.search(search_base, '(objectClass=inetOrgPerson)', SUBTREE,
                   attributes=['uid', 'cn', 'sn', 'givenName', 'mail', 'employeeNumber'])

        for entry in conn.entries:
            users.append({
                'uid': str(entry.uid) if hasattr(entry, 'uid') else '',
                'cn': str(entry.cn) if hasattr(entry, 'cn') else '',
                'sn': str(entry.sn) if hasattr(entry, 'sn') else '',
                'givenName': str(entry.givenName) if hasattr(entry, 'givenName') else '',
                'mail': str(entry.mail) if hasattr(entry, 'mail') else '',
                'employeeNumber': str(entry.employeeNumber) if hasattr(entry, 'employeeNumber') else ''
            })

        conn.unbind()
    except Exception as e:
        print(f"[ADMIN] Erreur lors de la récupération des utilisateurs: {e}")

    return render_template('admin_users.html', users=users, is_admin=True)

@app.route('/admin/users/add', methods=['POST'])
@login_required
def admin_add_user():
    """Ajouter un nouvel utilisateur LDAP."""
    if not is_admin():
        return jsonify({'error': 'Accès refusé'}), 403

    try:
        data = request.json
        uid = data.get('uid', '').strip()
        givenName = data.get('givenName', '').strip()
        sn = data.get('sn', '').strip()
        mail = data.get('mail', '').strip()
        password = data.get('password', '').strip()
        employeeNumber = data.get('employeeNumber', '').strip()

        if not all([uid, givenName, sn, password]):
            return jsonify({'error': 'Champs requis: uid, givenName, sn, password'}), 400

        host = app.config['LDAP_HOST']
        port = app.config['LDAP_PORT']
        use_ssl = app.config['LDAP_USE_SSL']
        base_dn = app.config['LDAP_BASE_DN']
        user_dn = app.config['LDAP_USER_DN']
        bind_dn = app.config['LDAP_BIND_USER_DN']
        bind_pwd = app.config['LDAP_BIND_USER_PASSWORD']

        server = Server(host, port=port, use_ssl=use_ssl, get_info=ALL)
        conn = Connection(server, bind_dn, bind_pwd, auto_bind=True)

        # Create DN for new user
        new_user_dn = f"uid={uid},{user_dn},{base_dn}"

        # Attributs de l'utilisateur
        attributes = {
            'objectClass': ['inetOrgPerson', 'posixAccount', 'top'],
            'uid': uid,
            'cn': f"{givenName} {sn}",
            'sn': sn,
            'givenName': givenName,
            'userPassword': password,
            'uidNumber': employeeNumber or '1000',
            'gidNumber': '1000',
            'homeDirectory': f'/home/{uid}'
        }

        if mail:
            attributes['mail'] = mail
        if employeeNumber:
            attributes['employeeNumber'] = employeeNumber

        # Ajouter l'utilisateur
        success = conn.add(new_user_dn, attributes=attributes)
        conn.unbind()

        if success:
            return jsonify({'success': True, 'message': f'Utilisateur {uid} créé avec succès'}), 201
        else:
            return jsonify({'error': 'Échec de la création de l\'utilisateur'}), 500

    except Exception as e:
        print(f"[ADMIN] Erreur lors de l'ajout d'utilisateur: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/users/delete', methods=['POST'])
@login_required
def admin_delete_user():
    """Supprimer un utilisateur LDAP."""
    if not is_admin():
        return jsonify({'error': 'Accès refusé'}), 403

    try:
        data = request.json
        uid = data.get('uid', '').strip()

        if not uid:
            return jsonify({'error': 'UID requis'}), 400

        host = app.config['LDAP_HOST']
        port = app.config['LDAP_PORT']
        use_ssl = app.config['LDAP_USE_SSL']
        base_dn = app.config['LDAP_BASE_DN']
        user_dn = app.config['LDAP_USER_DN']
        bind_dn = app.config['LDAP_BIND_USER_DN']
        bind_pwd = app.config['LDAP_BIND_USER_PASSWORD']

        server = Server(host, port=port, use_ssl=use_ssl, get_info=ALL)
        conn = Connection(server, bind_dn, bind_pwd, auto_bind=True)

        # DN de l'utilisateur à supprimer
        user_to_delete_dn = f"uid={uid},{user_dn},{base_dn}"

        # Supprimer l'utilisateur
        success = conn.delete(user_to_delete_dn)
        conn.unbind()

        if success:
            return jsonify({'success': True, 'message': f'Utilisateur {uid} supprimé avec succès'}), 200
        else:
            return jsonify({'error': 'Échec de la suppression de l\'utilisateur'}), 500

    except Exception as e:
        print(f"[ADMIN] Erreur lors de la suppression d'utilisateur: {e}")
        return jsonify({'error': str(e)}), 500

# =========================================
# SECURITY ADMINISTRATION
# =========================================
@app.route('/admin/security', methods=['GET'])
@login_required
def admin_security():
    """Page d'administration de la sécurité"""
    username = session.get('username')
    security_mgr = get_security_manager()

    # Get GLOBAL security mode (not user's mode)
    import sys
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)
    from lib.monitoring.admin_security import get_current_mode

    global_mode = get_current_mode()
    current_security_level = 'maximum' if global_mode == 'maximum' else 'standard'

    # Get registered devices
    devices = security_mgr.get_user_devices(username)

    # Statistiques globales (pour les admins)
    stats = {
        'total_users': len(security_mgr.users_security),
        'maximum_security_users': sum(1 for u in security_mgr.users_security.values()
                                      if u.get('level') == SECURITY_LEVEL_MAXIMUM),
        'total_devices': sum(len(devices) for devices in security_mgr.devices_registry.values())
    }

    # Configuration par utilisateur (pour les admins)
    users_config = []
    if is_admin():
        for user, config in security_mgr.users_security.items():
            users_config.append({
                'username': user,
                'security_level': config.get('level', SECURITY_LEVEL_STANDARD),
                'devices_count': len(security_mgr.devices_registry.get(user, {}))
            })

    message = request.args.get('message')

    return render_template('admin_security.html',
                         current_security_level=current_security_level,
                         devices=devices,
                         stats=stats,
                         users_config=users_config,
                         message=message,
                         is_admin=is_admin())

@app.route('/admin/security/set-level', methods=['POST'])
@login_required
def set_security_level():
    """Définit le niveau de sécurité GLOBAL pour TOUS les utilisateurs (admin uniquement)"""
    username = session.get('username')

    # Check that it's the admin
    if username != app.config['ADMIN_USERNAME']:
        return redirect(url_for('admin_security', message='Accès réservé à l\'administrateur'))

    security_level = request.form.get('security_level')

    if security_level not in [SECURITY_LEVEL_STANDARD, SECURITY_LEVEL_MAXIMUM]:
        return redirect(url_for('admin_security', message='Niveau de sécurité invalide'))

    security_mgr = get_security_manager()
    old_level = security_mgr.get_user_security_level(username)

    # IMPORTANT: Update global mode in .env
    import sys
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)
    from lib.monitoring.admin_security import get_current_mode
    from dotenv import set_key

    new_mode = 'maximum' if security_level == SECURITY_LEVEL_MAXIMUM else 'normal'
    set_key('.env', 'SECURITY_MODE', new_mode)
    print(f"[SECURITY] Mode global changé: {get_current_mode()} → {new_mode}")

    # Update ALL existing users
    updated_users = []

    # 1. Utilisateurs qui ont déjà un niveau de sécurité configuré
    if hasattr(security_mgr, 'users_security'):
        for user in list(security_mgr.users_security.keys()):
            security_mgr.set_user_security_level(user, security_level)
            updated_users.append(user)

    # 2. Utilisateurs qui ont des clés (donc qui se sont déjà connectés)
    if os.path.exists(USER_KEYS_DIR):
        for user_dir in os.listdir(USER_KEYS_DIR):
            user_path = os.path.join(USER_KEYS_DIR, user_dir)
            if os.path.isdir(user_path) and user_dir not in updated_users:
                security_mgr.set_user_security_level(user_dir, security_level)
                updated_users.append(user_dir)

    print(f"[SECURITY] {len(updated_users)} utilisateurs mis à jour vers {security_level}")

    # Si passage en mode sécurité maximale
    if old_level == SECURITY_LEVEL_STANDARD and security_level == SECURITY_LEVEL_MAXIMUM:
        print(f"[SECURITY] Passage en mode EXPERT - Déplacement des clés vers les utilisateurs (sauf admin)")

        # Déplacer les clés privées vers un backup (pas de suppression, juste déplacement)
        users_affected = []
        import shutil

        for user_dir in os.listdir(USER_KEYS_DIR):
            user_path = os.path.join(USER_KEYS_DIR, user_dir)
            if os.path.isdir(user_path):
                # Ne pas toucher à l'admin
                if user_dir == app.config['ADMIN_USERNAME']:
                    continue

                privkey_path = os.path.join(user_path, 'private_key.pem')
                if os.path.exists(privkey_path):
                    # Create backup (for return to standard mode)
                    backup_path = privkey_path + '.server_backup'

                    # Si un backup existe déjà, ne pas l'écraser (garder la clé originale)
                    if not os.path.exists(backup_path):
                        shutil.copy(privkey_path, backup_path)

                    # Supprimer du serveur (l'utilisateur devra la télécharger)
                    os.remove(privkey_path)
                    users_affected.append(user_dir)
                    print(f"[SECURITY] ✓ Clé privée retirée du serveur pour {user_dir} (backup créé)")

        # Message pour l'admin (en rouge)
        if username == app.config['ADMIN_USERNAME']:
            message = f'🔴 MODE EXPERT ACTIVÉ ! {len(users_affected)} utilisateur(s) devront télécharger leur clé privée EXISTANTE (pas de régénération). En tant qu\'admin, votre clé reste sur le serveur.'
        else:
            message = '🔴 MODE EXPERT ACTIVÉ ! Téléchargez votre clé privée lors de votre prochaine connexion. ⚠️ ATTENTION : C\'est votre clé EXISTANTE, vos anciens fichiers resteront accessibles !'

        print(f"[SECURITY] Mode expert activé - {len(users_affected)} utilisateurs affectés")

    # Si retour en mode standard
    elif old_level == SECURITY_LEVEL_MAXIMUM and security_level == SECURITY_LEVEL_STANDARD:
        print(f"[SECURITY] Retour en mode STANDARD - Restauration des clés sur le serveur")

        # Restaurer les clés privées de TOUS les utilisateurs depuis les backups
        users_restored = []
        users_missing = []
        import shutil

        for user_dir in os.listdir(USER_KEYS_DIR):
            user_path = os.path.join(USER_KEYS_DIR, user_dir)
            if os.path.isdir(user_path):
                privkey_path = os.path.join(user_path, 'private_key.pem')
                backup_path = privkey_path + '.server_backup'

                # If key doesn't already exist on server
                if not os.path.exists(privkey_path):
                    # Restaurer depuis le backup serveur
                    if os.path.exists(backup_path):
                        shutil.copy(backup_path, privkey_path)
                        users_restored.append(user_dir)
                        print(f"[SECURITY] ✓ Clé privée restaurée sur le serveur pour {user_dir}")
                    else:
                        # Pas de backup - l'utilisateur doit uploader sa clé
                        users_missing.append(user_dir)
                        print(f"[SECURITY] ⚠ Pas de backup pour {user_dir} - l'utilisateur doit uploader sa clé")

        # Message de confirmation
        if users_missing:
            message = f'🔴 MODE STANDARD ACTIVÉ ! {len(users_restored)} clé(s) restaurée(s). ⚠ {len(users_missing)} utilisateur(s) doivent uploader leur clé privée.'
        else:
            message = f'✅ MODE STANDARD ACTIVÉ ! Toutes les clés ({len(users_restored)}) ont été restaurées sur le serveur.'

        print(f"[SECURITY] Mode standard activé - {len(users_restored)} restaurées, {len(users_missing)} manquantes")

    else:
        message = '✅ Niveau de sécurité mis à jour avec succès'

    return redirect(url_for('admin_security', message=message))

@app.route('/admin/security/global-mode', methods=['GET', 'POST'])
@login_required
def admin_security_global_mode():
    """Gestion du mode de sécurité global (admin uniquement)"""
    username = session.get('username')
    
    if username != app.config['ADMIN_USERNAME']:
        return jsonify({'error': 'Accès réservé à l\'administrateur'}), 403
    
    # Import du module admin_security
    import sys
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)
    from lib.monitoring.admin_security import get_current_mode, get_users_with_files, change_security_mode
    
    if request.method == 'GET':
        # Afficher page de configuration
        current_mode = get_current_mode()
        users_with_files = get_users_with_files()
        
        return render_template('admin_security_mode.html',
                             current_mode=current_mode,
                             users_with_files=users_with_files,
                             users_count=len(users_with_files),
                             username=username)
    
    else:  # POST
        new_mode = request.form.get('mode')
        force_purge = request.form.get('force_purge') == 'true'
        
        result = change_security_mode(new_mode, username, force_purge)
        
        return jsonify(result)

@app.route('/admin/security/revoke-device', methods=['POST'])
@login_required
def revoke_device():
    """Révoque l'accès d'un appareil"""
    username = session.get('username')
    device_fingerprint = request.form.get('device_fingerprint')

    security_mgr = get_security_manager()
    success = security_mgr.revoke_device(username, device_fingerprint)

    if success:
        message = 'Appareil révoqué avec succès'
    else:
        message = 'Erreur lors de la révocation de l\'appareil'

    return redirect(url_for('admin_security', message=message))

@app.route('/register-device', methods=['POST'])
@login_required
def register_device():
    """Enregistre un nouvel appareil pour l'utilisateur"""
    username = session.get('username')
    security_mgr = get_security_manager()

    # Get fingerprint from form
    device_fp = request.form.get('device_fingerprint') or get_device_fingerprint()

    device_info = {
        'user_agent': request.headers.get('User-Agent', ''),
        'ip_address': request.remote_addr,
        'device_name': request.form.get('device_name', 'Unknown Device'),
        'has_private_key': request.form.get('has_private_key', 'false').lower() == 'true'
    }

    success = security_mgr.register_device(username, device_fp, device_info)

    return jsonify({'success': success})

@app.route('/admin/logs', methods=['GET'])
@login_required
def admin_logs():
    """Page des logs d'audit (Admin uniquement)"""
    if not is_admin():
        return redirect(url_for('index', message='Accès refusé'))

    logger = get_activity_logger()
    logs = logger.get_all_logs(limit=100)
    stats = logger.get_logs_stats()

    return render_template('admin_logs.html',
                         is_admin=True,
                         logs=logs,
                         stats=stats)

@app.route('/my-logs', methods=['GET'])
@login_required
def user_logs():
    """Page des logs pour l'utilisateur connecté"""
    username = session.get('username')
    is_admin = (username == app.config['ADMIN_USERNAME'])

    logger = get_activity_logger()
    logs = logger.get_user_logs(username, limit=100)
    stats = logger.get_logs_stats(username)
    alerts = logger.get_security_alerts(username)

    return render_template('user_logs.html',
                         username=username,
                         is_admin=is_admin,
                         logs=logs,
                         stats=stats,
                         alerts=alerts)

@app.route('/clear-my-logs', methods=['POST'])
@login_required
def clear_my_logs():
    """Efface les logs de l'utilisateur connecté"""
    username = session.get('username')
    logger = get_activity_logger()

    if logger.clear_logs(username):
        return redirect(url_for('user_logs') + '?message=Vos logs ont été effacés avec succès.')
    else:
        return redirect(url_for('user_logs') + '?message=Erreur lors de l\'effacement des logs.')

@app.route('/admin/clear-all-logs', methods=['POST'])
@login_required
def clear_all_logs():
    """Efface tous les logs (admin uniquement)"""
    if not is_admin():
        return redirect(url_for('admin_logs') + '?message=Accès refusé.')

    logger = get_activity_logger()

    if logger.clear_logs():  # Pas de username = efface tout
        return redirect(url_for('admin_logs') + '?message=Tous les logs ont été effacés avec succès.')
    else:
        return redirect(url_for('admin_logs') + '?message=Erreur lors de l\'effacement des logs.')

# =========================================
# CLIENT-SIDE DECRYPTION (Maximum Mode)
# =========================================
@app.route('/client-decrypt/<path:filepath>')
@login_required
def client_decrypt_file(filepath):
    """
    Page de déchiffrement côté client pour mode maximum
    L'utilisateur entre son mot de passe, le JS déchiffre et propose le téléchargement
    """
    username = session.get('username')

    # Passer le filepath au template
    return render_template('client_decrypt.html',
                         username=username,
                         filepath=filepath,
                         is_admin=username == app.config['ADMIN_USERNAME'])

@app.route('/api/get-encrypted-file/<path:filepath>')
@login_required
def get_encrypted_file(filepath):
    """
    Retourne le fichier chiffré (.enc) et la clé AES chiffrée (.key) en base64
    Pour le déchiffrement côté client
    """
    username = session.get('username')

    # Check access
    can_access, access_message, device_fp = check_security_access(username)
    if not can_access:
        return jsonify({'success': False, 'error': access_message}), 403

    # Construire les chemins
    if not filepath.endswith('.enc'):
        enc_filepath = filepath + ".enc"
        key_filepath = filepath + ".key"
    else:
        enc_filepath = filepath
        key_filepath = filepath.replace('.enc', '.key')

    try:
        import base64

        # Télécharger fichier chiffré (.enc)
        enc_data = None
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            start_command(s, 'G', username)
            send_prefixed_string(s, enc_filepath.replace('/', os.sep))
            filesize = struct.unpack('!Q', s.recv(8))[0]

            if filesize == 0:
                return jsonify({'success': False, 'error': 'Fichier .enc non trouvé'}), 404

            enc_data = b''
            rec, total = 0, filesize
            while rec < total:
                chunk = s.recv(4096)
                enc_data += chunk
                rec += len(chunk)

        # Télécharger clé AES chiffrée (.key)
        key_data = None
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            start_command(s, 'G', username)
            send_prefixed_string(s, key_filepath.replace('/', os.sep))
            keysize = struct.unpack('!Q', s.recv(8))[0]

            if keysize == 0:
                return jsonify({'success': False, 'error': 'Clé AES (.key) non trouvée'}), 404

            key_data = b''
            rec, total = 0, keysize
            while rec < total:
                chunk = s.recv(4096)
                key_data += chunk
                rec += len(chunk)

        # Retourner en base64
        return jsonify({
            'success': True,
            'filename': os.path.basename(filepath),
            'encrypted_file': base64.b64encode(enc_data).decode('utf-8'),
            'encrypted_key': base64.b64encode(key_data).decode('utf-8')
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# =========================================
# CLIENT DECRYPT VERSION
# =========================================
@app.route('/client-decrypt-version/<path:filepath>/<version>')
@login_required
def client_decrypt_version(filepath, version):
    """
    Page de déchiffrement côté client pour une version de fichier en mode maximum
    L'utilisateur entre son mot de passe, le JS déchiffre et propose le téléchargement
    """
    username = session.get('username')

    # Passer le filepath, la version et un flag au template
    return render_template('client_decrypt.html',
                         username=username,
                         filepath=filepath,
                         version=version,
                         is_version=True,
                         is_admin=username == app.config['ADMIN_USERNAME'])

@app.route('/api/get-encrypted-version/<path:filepath>/<version>')
@login_required
def get_encrypted_version(filepath, version):
    """
    Retourne une version de fichier chiffré (.enc) et la clé AES chiffrée (.key) en base64
    Pour le déchiffrement côté client des versions
    """
    username = session.get('username')

    # Check access
    can_access, access_message, device_fp = check_security_access(username)
    if not can_access:
        return jsonify({'success': False, 'error': access_message}), 403

    # Construire les chemins pour les versions
    if not filepath.endswith('.enc'):
        base_filepath = filepath
    else:
        base_filepath = filepath.replace('.enc', '')

    # Chemins dans .versions/
    enc_version_path = f".versions/{base_filepath}.enc/{version}.enc"
    key_version_path = f".versions/{base_filepath}.key/{version}.key"

    try:
        import base64

        # Télécharger fichier chiffré (.enc) de la version
        enc_data = None
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            start_command(s, 'G', username)
            send_prefixed_string(s, enc_version_path.replace('/', os.sep))
            filesize = struct.unpack('!Q', s.recv(8))[0]

            if filesize == 0:
                return jsonify({'success': False, 'error': 'Version .enc non trouvée'}), 404

            enc_data = b''
            rec, total = 0, filesize
            while rec < total:
                chunk = s.recv(4096)
                enc_data += chunk
                rec += len(chunk)

        # Télécharger clé AES chiffrée (.key) de la version
        key_data = None
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            start_command(s, 'G', username)
            send_prefixed_string(s, key_version_path.replace('/', os.sep))
            keysize = struct.unpack('!Q', s.recv(8))[0]

            if keysize == 0:
                return jsonify({'success': False, 'error': 'Clé AES (.key) de la version non trouvée'}), 404

            key_data = b''
            rec, total = 0, keysize
            while rec < total:
                chunk = s.recv(4096)
                key_data += chunk
                rec += len(chunk)

        # Retourner en base64
        return jsonify({
            'success': True,
            'filename': f"{os.path.basename(base_filepath)}_v{version}",
            'encrypted_file': base64.b64encode(enc_data).decode('utf-8'),
            'encrypted_key': base64.b64encode(key_data).decode('utf-8')
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# =========================================
# DOWNLOAD FOLDER (ZIP)
# =========================================
@app.route('/download_folder/<path:folderpath>')
@login_required
def download_folder(folderpath):
    """Télécharge un dossier complet sous forme de ZIP"""
    username = session.get('username')

    # Check access based on security level
    can_access, access_message, device_fp = check_security_access(username)
    if not can_access:
        return render_template('access_denied.html',
                             message=access_message,
                             username=username,
                             security_level=get_security_manager().get_user_security_level(username))

    # Check private key
    user_privkey_path = os.path.join(USER_KEYS_DIR, username, 'private_key.pem')
    if not os.path.exists(user_privkey_path):
        return redirect(url_for('setup_keys'))

    try:
        # Get file list in folder
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            start_command(s, 'L', username)
            list_size = struct.unpack('!I', s.recv(4))[0]
            enc_list = s.recv(list_size).decode('utf-8').split('\n') if list_size > 0 else []

        # Filtrer les fichiers du dossier demandé
        folder_files = [f for f in enc_list if f.endswith('.enc') and '.versions' not in f and f.startswith(folderpath.replace('/', os.sep))]

        if not folder_files:
            return "<h1>Erreur</h1><p>Dossier vide ou introuvable.</p>"

        # Create temporary ZIP file
        temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
        temp_zip_path = temp_zip.name
        temp_zip.close()

        download_dir = os.path.join(app.root_path, app.config['DOWNLOAD_FOLDER'])
        os.makedirs(download_dir, exist_ok=True)

        with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for enc_file in folder_files:
                # Retirer le .enc pour obtenir le nom original
                original_name = enc_file.replace('.enc', '').replace('\\', '/')

                # Télécharger et déchiffrer chaque fichier
                enc_filepath = enc_file.replace('\\', '/')
                key_filepath = enc_filepath.replace('.enc', '.key')

                # Télécharger fichier chiffré
                temp_enc_path = os.path.join(download_dir, os.path.basename(enc_filepath))
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
                    start_command(s, 'G', username)
                    send_prefixed_string(s, enc_filepath.replace('/', os.sep))
                    filesize = struct.unpack('!Q', s.recv(8))[0]

                    if filesize == 0:
                        continue  # Fichier introuvable, passer au suivant

                    with open(temp_enc_path, 'wb') as f:
                        rec, total = 0, filesize
                        while rec < total:
                            chunk = s.recv(4096)
                            f.write(chunk)
                            rec += len(chunk)

                # Télécharger clé AES
                temp_key_path = os.path.join(download_dir, os.path.basename(key_filepath))
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
                    start_command(s, 'G', username)
                    send_prefixed_string(s, key_filepath.replace('/', os.sep))
                    keysize = struct.unpack('!Q', s.recv(8))[0]

                    if keysize == 0:
                        os.remove(temp_enc_path)
                        continue  # Clé introuvable, passer au suivant

                    with open(temp_key_path, 'wb') as f:
                        rec, total = 0, keysize
                        while rec < total:
                            chunk = s.recv(4096)
                            f.write(chunk)
                            rec += len(chunk)

                # Déchiffrer
                temp_dec_path = dechiffrer_fichier_complet(
                    temp_enc_path,
                    temp_key_path,
                    user_privkey_path,
                    download_dir
                )

                if temp_dec_path:
                    # Ajouter au ZIP avec le chemin relatif
                    relative_path = original_name[len(folderpath)+1:] if original_name.startswith(folderpath + '/') else os.path.basename(original_name)
                    zipf.write(temp_dec_path, relative_path)

                    # Nettoyer les fichiers temporaires
                    os.remove(temp_dec_path)

                os.remove(temp_enc_path)
                os.remove(temp_key_path)

        # Logger le téléchargement
        logger = get_activity_logger()
        logger.log_activity(username, 'FOLDER_DOWNLOAD', request.remote_addr,
                          'SUCCESS', f'Dossier: {folderpath}',
                          user_agent=request.headers.get('User-Agent', ''))

        # Envoyer le ZIP
        folder_name = os.path.basename(folderpath) or 'files'
        response = send_file(temp_zip_path,
                           as_attachment=True,
                           download_name=f'{folder_name}.zip',
                           mimetype='application/zip')

        @response.call_on_close
        def cleanup():
            try:
                os.remove(temp_zip_path)
            except Exception as e:
                print(f"Erreur nettoyage ZIP {folderpath}: {e}")

        return response

    except Exception as e:
        print(f"[DOWNLOAD_FOLDER] Erreur: {e}")
        import traceback
        traceback.print_exc()
        return f"<h1>Erreur</h1><p>{e}</p>"

# =========================================
# STARTUP
# =========================================
if __name__ == '__main__':
    try:
        print("[DEBUG] URL MAP:", app.url_map)
    except Exception as _e:
        pass
    app.run(debug=True, host='0.0.0.0', port=APP_PORT)
