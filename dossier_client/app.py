from flask import Flask, render_template, request, session, redirect, url_for, send_from_directory, jsonify
from functools import wraps
from dotenv import load_dotenv
import socket
import os
import struct

import sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from crypto_utils import chiffrer_fichier as chiffrer_fichier_legacy, dechiffrer_fichier as dechiffrer_fichier_legacy
from client_crypto import chiffrer_fichier_complet, dechiffrer_fichier_complet
import re

# Charger les variables d'environnement
load_dotenv()

app = Flask(__name__)
APP_PORT = int(os.environ.get('FLASK_PORT', '5000'))

# =============================
# 🔧 CONFIGURATION FLASK & LDAP
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
# 🧪 MOCK LDAP (optionnel pour démo locale)
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
                        username = m_uid.group(1)
                    elif m_cn:
                        username = m_cn.group(1)
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
            username = m_uid.group(1) if m_uid else (m_cn.group(1) if m_cn else None)
            if username and 'userPassword' in current:
                users[username] = current['userPassword']
    return users

def mock_authenticate(username, password):
    ldif_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ldap', 'config', 'users.ldif')
    users = load_ldif_users(ldif_path)
    expected = users.get(username)
    return expected is not None and expected == password

# =========================================
# 🔧 OUTILS POUR LA COMMUNICATION SOCKET
# =========================================
def send_prefixed_string(sock, text):
    text_bytes = text.encode('utf-8')
    sock.sendall(struct.pack('!I', len(text_bytes)))
    sock.sendall(text_bytes)

def start_command(sock, command, username):
    sock.sendall(command.encode('utf-8'))
    send_prefixed_string(sock, username)

# =========================================
# 🔒 AUTHENTIFICATION & DÉCORATEURS
# =========================================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# =========================================
# 🩺 HEALTHCHECK
# =========================================
@app.route('/healthz', methods=['GET'])
def healthz():
    return 'ok', 200

# =========================================
# 🔎 LDAP HEALTH
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
# 🔐 ROUTE DE LOGIN
# =========================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username, password = request.form['username'], request.form['password']
        print("🔎 Tentative LDAP:", username)
        if USE_MOCK_LDAP:
            ok = mock_authenticate(username, password)
            print("[MOCK LDAP]", "success" if ok else "failure")
            if ok:
                session['logged_in'] = True
                session['username'] = username
                print(f"✅ (MOCK) Utilisateur {username} connecté avec succès.")
                return redirect(url_for('index'))
            print(f"❌ (MOCK) Échec d'authentification pour {username}.")
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
                        return redirect(url_for('index'))
                return render_template('login.html', error='LDAP injoignable.')

            if ldap_authenticate(username, password):
                session['logged_in'] = True
                session['username'] = username
                print(f"✅ Utilisateur {username} connecté.")
                # Verifier si les cles existent
                privkey = os.path.join(USER_KEYS_DIR, username, 'private_key.pem')
                if not os.path.exists(privkey):
                    return redirect(url_for('setup_keys'))
                return redirect(url_for('index'))
            else:
                print(f"❌ Échec auth pour {username}")
                return render_template('login.html', error='Identifiants invalides.')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# =========================================
# 🔑 SETUP DES CLES UTILISATEUR
# =========================================
def user_has_keys(username):
    """Verifie si l'utilisateur a ses cles generees."""
    privkey = os.path.join(USER_KEYS_DIR, username, 'private_key.pem')
    pubkey = os.path.join(USER_KEYS_DIR, username, 'public_key.pem')
    return os.path.exists(privkey) and os.path.exists(pubkey)

@app.route('/setup-keys')
@login_required
def setup_keys():
    username = session.get('username')
    if user_has_keys(username):
        return redirect(url_for('index'))
    return render_template('setup_keys.html', username=username)

@app.route('/generate-keys', methods=['POST'])
@login_required
def generate_keys():
    username = session.get('username')
    if user_has_keys(username):
        return jsonify({'success': True, 'message': 'Cles deja existantes'})

    try:
        user_keys_dir = os.path.join(USER_KEYS_DIR, username)
        os.makedirs(user_keys_dir, exist_ok=True)

        # Generer les cles X25519
        from client_crypto import generer_cles_utilisateur
        privkey_path, pubkey_path = generer_cles_utilisateur(user_keys_dir)

        # Copier la cle publique vers le storage serveur
        storage_user_dir = os.path.join(STORAGE_DIR, username)
        os.makedirs(storage_user_dir, exist_ok=True)
        import shutil
        shutil.copy(pubkey_path, os.path.join(storage_user_dir, 'public_key.pem'))

        # Envoyer la cle publique au serveur de stockage
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
                start_command(s, 'K', username)
                with open(pubkey_path, 'rb') as f:
                    pubkey_data = f.read()
                s.sendall(struct.pack('!I', len(pubkey_data)))
                s.sendall(pubkey_data)
            print(f"[KEYS] Cle publique envoyee au serveur pour {username}")
        except Exception as e:
            print(f"[KEYS] Erreur envoi cle publique: {e}")

        print(f"[KEYS] Cles generees pour {username}")
        return jsonify({'success': True})

    except Exception as e:
        print(f"[KEYS] Erreur generation: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/download-private-key')
@login_required
def download_private_key():
    """Telecharge la cle privee de l'utilisateur."""
    username = session.get('username')
    # Chemin absolu depuis /app
    privkey_path = os.path.join(USER_KEYS_DIR, username, 'private_key.pem')
    if not os.path.exists(privkey_path):
        return "Cle privee introuvable", 404
    from flask import send_file
    return send_file(
        privkey_path,
        as_attachment=True,
        download_name=f'{username}_private_key.pem'
    )

@app.route('/upload-private-key', methods=['POST'])
@login_required
def upload_private_key():
    """Upload temporaire de la cle privee pour dechiffrement."""
    username = session.get('username')
    if 'private_key' not in request.files:
        return jsonify({'success': False, 'error': 'Fichier manquant'})

    file = request.files['private_key']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'Fichier vide'})

    # Sauvegarder temporairement la cle
    user_keys_dir = os.path.join(USER_KEYS_DIR, username)
    os.makedirs(user_keys_dir, exist_ok=True)
    privkey_path = os.path.join(user_keys_dir, 'private_key.pem')
    file.save(privkey_path)
    os.chmod(privkey_path, 0o600)

    print(f"[KEYS] Cle privee uploadee pour {username}")
    return jsonify({'success': True})

@app.route('/need-private-key')
@login_required
def need_private_key():
    """Page demandant l'upload de la cle privee."""
    filename = request.args.get('filename', '')
    action = request.args.get('action', 'download')
    redirect_url = url_for('download_file', filepath=filename) if action == 'download' else '/'
    return render_template('upload_key.html', filename=filename, redirect_url=redirect_url)

# =========================================
# 🏠 PAGE D'ACCUEIL
# =========================================
@app.route('/')
@login_required
def index():
    username = session.get('username')
    is_admin = (username == app.config['ADMIN_USERNAME'])
    return render_template('index.html', username=username, is_admin=is_admin)

# =========================================
# 📤 UPLOAD DE FICHIERS
# =========================================
@app.route('/upload', methods=['POST'])
@login_required
def upload_files():
    files = request.files.getlist('files_to_upload')
    if not files or files[0].filename == '':
        return render_template('index.html', username=session.get('username'),
            message="Erreur : Aucun fichier/dossier sélectionné.")

    username = session.get('username')
    count = 0

    # Vérifier la clé publique de l'utilisateur
    user_pubkey_path = os.path.join(USER_KEYS_DIR, username, 'public_key.pem')
    print(f"[UPLOAD X25519] Utilisateur : {username}")
    print(f"[UPLOAD X25519] Clé publique : {user_pubkey_path}")

    if not os.path.exists(user_pubkey_path):
        print(f"[UPLOAD X25519] ❌ Clé publique introuvable")
        return render_template('index.html', username=username,
            is_admin=(username == app.config['ADMIN_USERNAME']),
            message=f"Erreur : Clé publique introuvable. Exécutez './generate_user_keys.sh {username}'")

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
                    print(f"[UPLOAD X25519] ✅ Chiffrement réussi, envoi au serveur...")
                    # Upload fichier chiffré
                    start_command(s, 'F', username)
                    enc_rel_path = file.filename + ".enc"
                    send_prefixed_string(s, enc_rel_path)
                    filesize = os.path.getsize(fichier_enc_path)
                    s.sendall(struct.pack('!Q', filesize))
                    with open(fichier_enc_path, 'rb') as f_enc:
                        while chunk := f_enc.read(4096):
                            s.sendall(chunk)

                    # Upload clé AES chiffrée
                    print(f"[UPLOAD X25519] Upload de la clé AES chiffrée...")
                    start_command(s, 'F', username)
                    key_rel_path = file.filename + ".key"
                    send_prefixed_string(s, key_rel_path)
                    keysize = os.path.getsize(cle_aes_enc_path)
                    s.sendall(struct.pack('!Q', keysize))
                    with open(cle_aes_enc_path, 'rb') as f_key:
                        while chunk := f_key.read(4096):
                            s.sendall(chunk)
                    print(f"[UPLOAD X25519] ✅ Clé uploadée : {key_rel_path}")

                    count += 1
                    print(f"[UPLOAD X25519] ✅ Fichier complet uploadé (enc + key)")

                    # Nettoyage
                    os.remove(fichier_enc_path)
                    os.remove(cle_aes_enc_path)
                else:
                    print(f"[UPLOAD X25519] ❌ Chiffrement échoué pour {file.filename}")

                os.remove(temp_orig_path)

            s.sendall(b'E')
        msg = f"Succès : {count}/{len(files)} fichier(s) envoyé(s) de manière sécurisée."
        is_admin = (username == app.config['ADMIN_USERNAME'])
        return render_template('index.html', username=username, is_admin=is_admin, message=msg)
    except Exception as e:
        is_admin = (username == app.config['ADMIN_USERNAME'])
        return render_template('index.html', username=username, is_admin=is_admin, message=f"Erreur Critique : {e}")

# =========================================
# 📥 RESTAURATION
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

        return render_template('restore.html',
                             files=file_list,
                             folders=folder_list,
                             current_path=current_path,
                             breadcrumb=breadcrumb,
                             parent_path=parent_path,
                             is_admin=is_admin,
                             username=username,
                             message=message)
    except Exception as e:
        return f"<h1>Erreur de connexion</h1><p>{e}</p>"

# =========================================
# 🗂️ VERSIONS: LISTE, TÉLÉCHARGEMENT, RESTAURATION
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

            # Récupérer les versions pour chaque fichier du niveau courant
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

    # Ajouter .enc seulement si nécessaire
    if not filepath.endswith('.enc'):
        enc_filepath = filepath + ".enc"
    else:
        enc_filepath = filepath

    # Utiliser des séparateurs URL, puis convertir côté envoi
    rel_path = '.versions/' + enc_filepath.replace('\\', '/') + '/' + f"{version}.enc"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            start_command(s, 'G', username)
            send_prefixed_string(s, rel_path.replace('/', os.sep))
            filesize = struct.unpack('!Q', s.recv(8))[0]

            # Si version .enc non trouvée, essayer sans .enc
            if filesize == 0:
                rel_path_no_enc = '.versions/' + filepath.replace('\\', '/') + '/' + f"{version}"
                s.close()
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
                    s2.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
                    start_command(s2, 'G', username)
                    send_prefixed_string(s2, rel_path_no_enc.replace('/', os.sep))
                    filesize = struct.unpack('!Q', s2.recv(8))[0]

                    if filesize == 0:
                        return "<h1>Erreur</h1><p>Version introuvable sur le serveur.</p>"

                    download_dir = os.path.join(app.root_path, app.config['DOWNLOAD_FOLDER'])
                    os.makedirs(download_dir, exist_ok=True)
                    temp_name = f"{os.path.basename(filepath)}.v{version}"
                    temp_path = os.path.join(download_dir, temp_name)

                    with open(temp_path, 'wb') as f:
                        rec, total = 0, filesize
                        while rec < total:
                            chunk = s2.recv(4096)
                            f.write(chunk)
                            rec += len(chunk)

                    # Version non chiffrée
                    from flask import send_file
                    response = send_file(temp_path, as_attachment=True, download_name=os.path.basename(filepath))

                    @response.call_on_close
                    def cleanup():
                        try:
                            os.remove(temp_path)
                        except Exception as e:
                            print(f"Erreur nettoyage version {filepath}@{version}: {e}")

                    return response

            download_dir = os.path.join(app.root_path, app.config['DOWNLOAD_FOLDER'])
            os.makedirs(download_dir, exist_ok=True)
            temp_enc_name = f"{os.path.basename(filepath)}.v{version}.enc"
            temp_enc_path = os.path.join(download_dir, temp_enc_name)

            with open(temp_enc_path, 'wb') as f:
                rec, total = 0, filesize
                while rec < total:
                    chunk = s.recv(4096)
                    f.write(chunk)
                    rec += len(chunk)

        temp_dec_name = f"{os.path.basename(filepath)}.v{version}"
        temp_dec_path = os.path.join(download_dir, temp_dec_name)

        # Essayer de déchiffrer
        decrypt_success = dechiffrer_fichier(temp_enc_path, temp_dec_path)

        from flask import send_file

        if decrypt_success:
            # Version déchiffrée avec succès
            response = send_file(temp_dec_path, as_attachment=True, download_name=os.path.basename(filepath))

            @response.call_on_close
            def cleanup():
                try:
                    os.remove(temp_enc_path)
                    os.remove(temp_dec_path)
                except Exception as e:
                    print(f"Erreur nettoyage version {filepath}@{version}: {e}")

            return response
        else:
            # Déchiffrement échoué, probablement version non chiffrée
            print(f"[DOWNLOAD_VERSION] Déchiffrement échoué, envoi du fichier brut")
            response = send_file(temp_enc_path, as_attachment=True, download_name=os.path.basename(filepath))

            @response.call_on_close
            def cleanup():
                try:
                    os.remove(temp_enc_path)
                    if os.path.exists(temp_dec_path):
                        os.remove(temp_dec_path)
                except Exception as e:
                    print(f"Erreur nettoyage version {filepath}@{version}: {e}")

            return response
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
# 🗑️ DELETE (admin seulement)
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
# 📦 DOWNLOAD
# =========================================
@app.route('/download/<path:filepath>')
@login_required
def download_file(filepath):
    username = session.get('username')

    # Vérifier la clé privée de l'utilisateur
    user_privkey_path = os.path.join(USER_KEYS_DIR, username, 'private_key.pem')
    if not os.path.exists(user_privkey_path):
        return redirect(url_for('need_private_key', filename=filepath, action='download'))

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
# 🔍 API DE RECHERCHE GLOBALE
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
# 🚀 DÉMARRAGE
# =========================================
if __name__ == '__main__':
    try:
        print("[DEBUG] URL MAP:", app.url_map)
    except Exception as _e:
        pass
    app.run(debug=True, host='0.0.0.0', port=APP_PORT)
