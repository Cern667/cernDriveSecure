from flask import Flask, render_template, request, session, redirect, url_for, send_from_directory
from functools import wraps
from dotenv import load_dotenv
import socket
import os
import struct
from flask_ldap3_login import LDAP3LoginManager

from ..crypto_utils import chiffrer_fichier, dechiffrer_fichier

load_dotenv()
app = Flask(__name__)
app.config.from_prefixed_env('FLASK')  # Charge les variables d'env préfixées par FLASK_
app.config['ADMIN_USERNAME'] = os.getenv('ADMIN_USERNAME')
STORAGE_SERVER_IP = '127.0.0.1'
STORAGE_SERVER_PORT = 65432
app.config['UPLOAD_FOLDER'] = 'temp_uploads'
app.config['DOWNLOAD_FOLDER'] = 'temp_downloads'

ldap_manager = LDAP3LoginManager(app)


def send_prefixed_string(sock, text):
    text_bytes = text.encode('utf-8')
    sock.sendall(struct.pack('!I', len(text_bytes)))
    sock.sendall(text_bytes)


def start_command(sock, command, username):
    sock.sendall(command.encode('utf-8'))
    send_prefixed_string(sock, username)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session: return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username, password = request.form['username'], request.form['password']
        response = ldap_manager.authenticate(username, password)
        if response.status == 'success':
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('index'))
        return render_template('login.html', error='Identifiants LDAP invalides.')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear();
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    return render_template('index.html', username=session.get('username'))


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
                        while chunk := f_enc.read(4096): s.sendall(chunk)
                    count += 1
                os.remove(temp_orig_path)
                if os.path.exists(temp_enc_path): os.remove(temp_enc_path)
            s.sendall(b'E')
        msg = f"Succès : {count}/{len(files)} fichier(s) envoyé(s) de manière sécurisée."
        return render_template('index.html', username=username, message=msg)
    except Exception as e:
        return render_template('index.html', username=username, message=f"Erreur Critique : {e}")


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
        file_list = [f.replace('.enc', '') for f in enc_list if f.endswith('.enc')]
        is_admin = (username == app.config['ADMIN_USERNAME'])
        return render_template('restore.html', files=file_list, is_admin=is_admin, username=username)
    except Exception as e:
        return f"<h1>Erreur de connexion</h1><p>{e}</p>"


@app.route('/download/<path:filepath>')
@login_required
def download_file(filepath):
    username = session.get('username')
    enc_filepath = filepath + ".enc"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            start_command(s, 'G', username)
            send_prefixed_string(s, enc_filepath)
            filesize = struct.unpack('!Q', s.recv(8))[0]
            if filesize == 0: return "<h1>Erreur</h1><p>Fichier non trouvé sur le serveur.</p>"
            os.makedirs(app.config['DOWNLOAD_FOLDER'], exist_ok=True)
            temp_enc_path = os.path.join(app.config['DOWNLOAD_FOLDER'], os.path.basename(enc_filepath))
            with open(temp_enc_path, 'wb') as f:
                rec, total = 0, filesize
                while rec < total:
                    chunk = s.recv(4096);
                    f.write(chunk);
                    rec += len(chunk)

        temp_dec_path = os.path.join(app.config['DOWNLOAD_FOLDER'], os.path.basename(filepath))
        if not dechiffrer_fichier(temp_enc_path, temp_dec_path):
            os.remove(temp_enc_path)
            return "<h1>Erreur de Déchiffrement</h1>"

        response = send_from_directory(app.config['DOWNLOAD_FOLDER'], os.path.basename(filepath), as_attachment=True)

        @response.call_on_close
        def cleanup():
            try:
                os.remove(temp_enc_path);
                os.remove(temp_dec_path)
            except Exception as e:
                print(f"Erreur nettoyage {filepath}: {e}")

        return response
    except Exception as e:
        return f"<h1>Erreur</h1><p>{e}</p>"


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
