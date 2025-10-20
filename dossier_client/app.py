from flask import Flask, render_template, request, send_from_directory
import socket
import os
import struct

# --- CONFIGURATION ---
# L'adresse IP de votre VRAI serveur (celui qui exécute server.py)
STORAGE_SERVER_IP = '127.0.0.1'
STORAGE_SERVER_PORT = 65432

app = Flask(__name__)
# Dossiers temporaires que Flask utilisera. Ils seront créés automatiquement.
app.config['UPLOAD_FOLDER'] = 'temp_uploads'
app.config['DOWNLOAD_FOLDER'] = 'temp_downloads'


def send_file_to_storage_server(sock, file_path):
    """
    Fonction helper pour envoyer un fichier au serveur de stockage.
    Utilise le protocole: [F] [longueur nom] [nom] [taille fichier] [contenu fichier]
    """
    try:
        filename = os.path.basename(file_path)
        # 1. Envoyer le type de message 'F' (Fichier)
        sock.sendall(b'F')

        # 2. Envoyer le nom du fichier
        filename_bytes = filename.encode('utf-8')
        sock.sendall(struct.pack('!I', len(filename_bytes)))
        sock.sendall(filename_bytes)

        # 3. Envoyer la taille et le contenu du fichier
        filesize = os.path.getsize(file_path)
        sock.sendall(struct.pack('!Q', filesize))
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                sock.sendall(chunk)
        print(f"  -> Fichier '{filename}' envoyé au serveur de stockage.")
        return True
    except Exception as e:
        print(f"❌ Erreur lors de l'envoi de '{filename}' : {e}")
        return False


@app.route('/')
def index():
    """Affiche la page d'accueil pour l'envoi de fichiers."""
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_files():
    """Gère l'envoi de fichiers du navigateur vers le serveur de stockage."""
    uploaded_files = request.files.getlist('files_to_upload')

    if not uploaded_files or uploaded_files[0].filename == '':
        return render_template('index.html', message="Erreur : Vous n'avez sélectionné aucun fichier.")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            files_sent_count = 0

            for file in uploaded_files:
                temp_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
                file.save(temp_path)
                if send_file_to_storage_server(s, temp_path):
                    files_sent_count += 1
                os.remove(temp_path)  # Nettoyage du fichier temporaire

            s.sendall(b'E')  # Signal de fin de transmission

        message = f"Succès : {files_sent_count}/{len(uploaded_files)} fichier(s) envoyé(s)."
        return render_template('index.html', message=message)

    except ConnectionRefusedError:
        message = "Erreur Critique : La connexion au serveur de stockage a été refusée. Est-il bien démarré ?"
        return render_template('index.html', message=message)
    except Exception as e:
        message = f"Une erreur inattendue est survenue : {e}"
        return render_template('index.html', message=message)


@app.route('/restore')
def restore_page():
    """NOUVEAU: Affiche la page listant les fichiers disponibles pour la restauration."""
    file_list = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            s.sendall(b'L')  # Envoyer la commande 'Liste'

            # Recevoir la réponse du serveur
            list_size_data = s.recv(4)
            list_size = struct.unpack('!I', list_size_data)[0]
            if list_size > 0:
                file_list_bytes = s.recv(list_size)
                file_list = file_list_bytes.decode('utf-8').split('\n')

        return render_template('restore.html', files=file_list)
    except Exception as e:
        # Affiche une page d'erreur si la connexion au serveur de stockage échoue
        return f"<h1>Erreur de connexion au serveur de stockage</h1><p>Impossible de récupérer la liste des fichiers.</p><p>Détails: {e}</p>"


@app.route('/download/<path:filename>')
def download_file(filename):
    """NOUVEAU: Gère la demande de téléchargement d'un fichier spécifique."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((STORAGE_SERVER_IP, STORAGE_SERVER_PORT))
            s.sendall(b'G')  # Envoyer la commande 'Get'

            # Envoyer le nom du fichier demandé
            filename_bytes = filename.encode('utf-8')
            s.sendall(struct.pack('!I', len(filename_bytes)))
            s.sendall(filename_bytes)

            # Recevoir le fichier du serveur
            filesize_data = s.recv(8)
            filesize = struct.unpack('!Q', filesize_data)[0]

            if filesize == 0:
                return "<h1>Erreur</h1><p>Fichier non trouvé sur le serveur de stockage.</p>"

            # Créer le dossier de téléchargement temporaire si nécessaire
            os.makedirs(app.config['DOWNLOAD_FOLDER'], exist_ok=True)
            download_path = os.path.join(app.config['DOWNLOAD_FOLDER'], filename)

            # Écrire le fichier reçu dans le dossier temporaire
            with open(download_path, 'wb') as f:
                received = 0
                while received < filesize:
                    chunk = s.recv(4096)
                    if not chunk: break
                    f.write(chunk)
                    received += len(chunk)

            # Utiliser Flask pour envoyer ce fichier temporaire au navigateur, puis le supprimer
            # as_attachment=True force le dialogue "Enregistrer sous..."
            response = send_from_directory(app.config['DOWNLOAD_FOLDER'], filename, as_attachment=True)

            # Une fois la réponse envoyée, on peut essayer de nettoyer
            @response.call_on_close
            def cleanup():
                try:
                    os.remove(download_path)
                except Exception as e:
                    print(f"Erreur lors du nettoyage du fichier téléchargé {download_path}: {e}")

            return response

    except Exception as e:
        return f"<h1>Erreur</h1><p>Impossible de télécharger le fichier.</p><p>Détails: {e}</p>"


if __name__ == '__main__':
    # host='0.0.0.0' rend l'application accessible depuis d'autres machines sur le réseau
    app.run(debug=True, host='0.0.0.0', port=5000)