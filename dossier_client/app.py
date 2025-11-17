from flask import Flask, render_template, request, session, redirect, url_for, send_from_directory
from functools import wraps
from dotenv import load_dotenv
import socket
import os
import struct
from flask_ldap3_login import LDAP3LoginManager

import sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from crypto_utils import chiffrer_fichier, dechiffrer_fichier
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

# Initialiser le gestionnaire LDAP
ldap_manager = LDAP3LoginManager(app)

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
            # Authentification LDAP réelle
            try:
                print("[LDAP] host=", app.config.get("LDAP_HOST"),
                      "port=", app.config.get("LDAP_PORT"),
                      "ssl=", app.config.get("LDAP_USE_SSL"),
                      "base_dn=", app.config.get("LDAP_BASE_DN"),
                      "user_dn=", app.config.get("LDAP_USER_DN"),
                      "rdn_attr=", app.config.get("LDAP_USER_RDN_ATTR"),
                      "login_attr=", app.config.get("LDAP_USER_LOGIN_ATTR"))
                # Vérifier joignabilité avant de tenter l'auth
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
                        return render_template('login.html', error='LDAP injoignable; identifiants LDIF invalides.')
                response = ldap_manager.authenticate(username, password)
                # Log étendu
                try:
                    print("[LDAP] status=", getattr(response, 'status', None),
                          "error=", getattr(response, 'error', None),
                          "user_info=", getattr(response, 'user_info', None))
                except Exception:
                    pass

                if getattr(response, 'status', None) == 'success':
                    session['logged_in'] = True
                    session['username'] = username
                    print(f"✅ Utilisateur {username} connecté avec succès.")
                    return redirect(url_for('index'))

                err = getattr(response, 'error', None)
                print(f"❌ Échec d'authentification pour {username}.", err)
                # Détection de problème réseau LDAP (aucun serveur joignable)
                if not err:
                    try:
                        with socket.create_connection((app.config['LDAP_HOST'], app.config['LDAP_PORT']), timeout=3):
                            pass
                        # Le serveur est joignable, donc le problème est probablement lié aux identifiants / DN
                    except Exception as net_e:
                        err = f"Impossible de contacter le serveur LDAP: {app.config['LDAP_HOST']}:{app.config['LDAP_PORT']} ({net_e})"
                return render_template('login.html', error=err or 'Identifiants LDAP invalides.')
            except Exception as e:
                print("[LDAP] Exception:", e)
                return render_template('login.html', error=f"Erreur de connexion au LDAP: {e}")

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

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
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            for file in files:
                temp_orig_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(file.filename))
                file.save(temp_orig_path)
                temp_enc_path = temp_orig_path + ".enc"
                if chiffrer_fichier(temp_orig_path, temp_enc_path):
                    start_command(s, 'F', username)
                    enc_rel_path = file.filename + ".enc"
                    send_prefixed_string(s, enc_rel_path)
                    filesize = os.path.getsize(temp_enc_path)
                    s.sendall(struct.pack('!Q', filesize))
                    with open(temp_enc_path, 'rb') as f_enc:
                        while chunk := f_enc.read(4096):
                            s.sendall(chunk)
                    count += 1
                os.remove(temp_orig_path)
                if os.path.exists(temp_enc_path):
                    os.remove(temp_enc_path)
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
@login_required
def restore_page():
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
        file_list = [f.replace('.enc', '').replace('\\', '/') for f in base_enc_list]
        is_admin = (username == app.config['ADMIN_USERNAME'])
        message = request.args.get('message')
        return render_template('restore.html', files=file_list, is_admin=is_admin, username=username, message=message)
    except Exception as e:
        return f"<h1>Erreur de connexion</h1><p>{e}</p>"

# =========================================
# 🗂️ VERSIONS: LISTE, TÉLÉCHARGEMENT, RESTAURATION
# =========================================
@app.route('/versions')
@login_required
def versions_page():
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
            files = [f.replace('.enc', '').replace('\\', '/') for f in base_enc_list]

            # Récupérer les versions pour chaque fichier
            versions_map = {}
            for enc_path in base_enc_list:
                if not enc_path.endswith('.enc'):
                    continue
                start_command(s, 'V', username)
                send_prefixed_string(s, enc_path)
                vlen = struct.unpack('!I', s.recv(4))[0]
                versions = s.recv(vlen).decode('utf-8').split('\n') if vlen > 0 else []
                # versions sont des timestamps 'YYYYMMDD-HHMMSS'
                versions_map[enc_path.replace('.enc', '').replace('\\', '/')] = versions
            s.sendall(b'E')

        is_admin = (username == app.config['ADMIN_USERNAME'])
        message = request.args.get('message')
        return render_template('versions.html', files=files, versions_map=versions_map, is_admin=is_admin, username=username, message=message)
    except Exception as e:
        return f"<h1>Erreur</h1><p>{e}</p>"


@app.route('/download_version/<path:filepath>/<version>')
@login_required
def download_version(filepath, version):
    username = session.get('username')
    enc_filepath = filepath + ".enc"
    # Utiliser des séparateurs URL, puis convertir côté envoi
    rel_path = '.versions/' + enc_filepath.replace('\\', '/') + '/' + f"{version}.enc"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            start_command(s, 'G', username)
            send_prefixed_string(s, rel_path.replace('/', os.sep))
            filesize = struct.unpack('!Q', s.recv(8))[0]
            if filesize == 0:
                return "<h1>Erreur</h1><p>Version introuvable sur le serveur.</p>"
            download_dir = os.path.join(app.root_path, app.config['DOWNLOAD_FOLDER'])
            os.makedirs(download_dir, exist_ok=True)
            temp_enc_name = f"{os.path.basename(filepath)}.{version}.enc"
            temp_enc_path = os.path.join(download_dir, temp_enc_name)
            with open(temp_enc_path, 'wb') as f:
                rec, total = 0, filesize
                while rec < total:
                    chunk = s.recv(4096)
                    f.write(chunk)
                    rec += len(chunk)

        temp_dec_name = f"{os.path.basename(filepath)}.{version}"
        temp_dec_path = os.path.join(download_dir, temp_dec_name)
        if not dechiffrer_fichier(temp_enc_path, temp_dec_path):
            os.remove(temp_enc_path)
            return "<h1>Erreur de Déchiffrement</h1>"

        from flask import send_file
        response = send_file(temp_dec_path, as_attachment=True, download_name=os.path.basename(filepath))

        @response.call_on_close
        def cleanup():
            try:
                os.remove(temp_enc_path)
                os.remove(temp_dec_path)
            except Exception as e:
                print(f"Erreur nettoyage version {filepath}@{version}: {e}")

        return response
    except Exception as e:
        return f"<h1>Erreur</h1><p>{e}</p>"


@app.route('/restore_version', methods=['POST'])
@login_required
def restore_version():
    username = session.get('username')
    filepath = request.form.get('filepath')
    version = request.form.get('version')
    if not filepath or not version:
        return redirect(url_for('versions_page', message='Paramètres manquants.'))
    enc_filepath = filepath + ".enc"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            start_command(s, 'R', username)
            # Convertir chemin URL -> OS pour le serveur
            send_prefixed_string(s, enc_filepath.replace('/', os.sep))
            send_prefixed_string(s, version)
            # Lire ACK
            try:
                ack_len = struct.unpack('!I', s.recv(4))[0]
                ack_msg = s.recv(ack_len).decode('utf-8') if ack_len > 0 else ''
            except Exception:
                ack_msg = ''
            s.sendall(b'E')
        msg = 'Version restaurée avec succès.' if ack_msg == 'OK' else (ack_msg or 'Restauration effectuée.')
        return redirect(url_for('versions_page', message=msg))
    except Exception as e:
        return redirect(url_for('versions_page', message=f'Erreur: {e}'))

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
    if not filepath or not version:
        return redirect(url_for('versions_page', message='Paramètres manquants.'))
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
        return redirect(url_for('versions_page', message=msg))
    except Exception as e:
        return redirect(url_for('versions_page', message=f'Erreur: {e}'))

@app.route('/delete_file', methods=['POST'])
@login_required
def delete_file_route():
    username = session.get('username')
    if username != app.config['ADMIN_USERNAME']:
        return redirect(url_for('restore_page', message='Action réservée à l\'admin.'))
    filepath = request.form.get('filepath')
    if not filepath:
        return redirect(url_for('restore_page', message='Paramètres manquants.'))
    enc_filepath = (filepath + ".enc").replace('/', os.sep)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            start_command(s, 'D', username)
            send_prefixed_string(s, enc_filepath)
            try:
                ack_len = struct.unpack('!I', s.recv(4))[0]
                ack_msg = s.recv(ack_len).decode('utf-8') if ack_len > 0 else ''
            except Exception:
                ack_msg = ''
            s.sendall(b'E')
        msg = 'Fichier supprimé.' if ack_msg == 'OK' else (ack_msg or 'Suppression effectuée.')
        return redirect(url_for('restore_page', message=msg))
    except Exception as e:
        return redirect(url_for('restore_page', message=f'Erreur: {e}'))

# =========================================
# 📦 DOWNLOAD
# =========================================
@app.route('/download/<path:filepath>')
@login_required
def download_file(filepath):
    username = session.get('username')
    enc_filepath = filepath + ".enc"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            start_command(s, 'G', username)
            # Convertir en séparateurs OS pour le serveur
            send_prefixed_string(s, enc_filepath.replace('/', os.sep))
            filesize = struct.unpack('!Q', s.recv(8))[0]
            if filesize == 0:
                return "<h1>Erreur</h1><p>Fichier non trouvé sur le serveur.</p>"
            download_dir = os.path.join(app.root_path, app.config['DOWNLOAD_FOLDER'])
            os.makedirs(download_dir, exist_ok=True)
            temp_enc_path = os.path.join(download_dir, os.path.basename(enc_filepath))
            with open(temp_enc_path, 'wb') as f:
                rec, total = 0, filesize
                while rec < total:
                    chunk = s.recv(4096)
                    f.write(chunk)
                    rec += len(chunk)

        temp_dec_path = os.path.join(download_dir, os.path.basename(filepath))
        if not dechiffrer_fichier(temp_enc_path, temp_dec_path):
            os.remove(temp_enc_path)
            return "<h1>Erreur de Déchiffrement</h1>"

        from flask import send_file
        response = send_file(temp_dec_path, as_attachment=True, download_name=os.path.basename(filepath))

        @response.call_on_close
        def cleanup():
            try:
                os.remove(temp_enc_path)
                os.remove(temp_dec_path)
            except Exception as e:
                print(f"Erreur nettoyage {filepath}: {e}")

        return response
    except Exception as e:
        return f"<h1>Erreur</h1><p>{e}</p>"

# =========================================
# 🚀 DÉMARRAGE
# =========================================
if __name__ == '__main__':
    try:
        print("[DEBUG] URL MAP:", app.url_map)
    except Exception as _e:
        pass
    app.run(debug=True, host='0.0.0.0', port=APP_PORT)
