# dossier_server/server.py
import socket
import os
import struct
from datetime import datetime
from dotenv import load_dotenv


def start_server(host='0.0.0.0', port=65432):
    load_dotenv()
    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")  # Valeur par défaut si non définie
    storage_directory = os.path.abspath("storage")
    if not os.path.exists(storage_directory): os.makedirs(storage_directory)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()
    print(f"✅ Serveur Multi-Utilisateurs démarré. Admin='{ADMIN_USERNAME}'. En écoute sur {host}:{port}")

    while True:
        try:
            conn, addr = server_socket.accept()
            handle_client(conn, addr, storage_directory, ADMIN_USERNAME)
        except KeyboardInterrupt:
            break
    server_socket.close()


def recv_prefixed_string(conn):
    len_data = conn.recv(4);
    if not len_data: return None
    str_len = struct.unpack('!I', len_data)[0]
    return conn.recv(str_len).decode('utf-8')


def handle_client(conn, addr, storage_directory, admin_username):
    print(f"\n[CONNEXION] Reçue de {addr}")
    try:
        while True:
            print(f"  [SERVEUR] Attente commande...")
            message_type = conn.recv(1)
            print(f"  [SERVEUR] Commande reçue : {message_type}")
            if not message_type or message_type == b'E':
                if message_type == b'E': print("✅ Le client a terminé la transmission.")
                break

            username = recv_prefixed_string(conn)
            if not username: break
            print(f"  -> Requête de l'utilisateur '{username}'")

            user_base_dir = storage_directory if username == admin_username else os.path.join(storage_directory,
                                                                                              username)
            os.makedirs(user_base_dir, exist_ok=True)

            if message_type == b'F':
                handle_file_upload(conn, user_base_dir)
            elif message_type == b'K':
                # Nouvelle commande : upload de clé publique
                handle_pubkey_upload(conn, user_base_dir)
            elif message_type == b'P':
                # Nouvelle commande : récupérer clé publique
                handle_pubkey_download(conn, user_base_dir)
            elif message_type == b'L':
                handle_list_files(conn, user_base_dir, username, admin_username, storage_directory)
            elif message_type == b'G':
                handle_file_download(conn, user_base_dir)
            elif message_type == b'V':
                handle_list_versions(conn, user_base_dir)
            elif message_type == b'R':
                handle_restore_version(conn, user_base_dir)
            elif message_type == b'D':
                handle_delete_file(conn, user_base_dir, username, admin_username)
            elif message_type == b'M':
                handle_delete_folder(conn, user_base_dir, username, admin_username)
            elif message_type == b'X':
                handle_delete_version(conn, user_base_dir, username, admin_username)

    except Exception as e:
        print(f"❌ Erreur avec {addr}: {e}")
    finally:
        print(f"[CONNEXION FERMÉE] pour {addr}"); conn.close()


def safe_join(base, path):
    final_path = os.path.abspath(os.path.join(base, path))
    if os.path.commonprefix([final_path, base]) != base:
        raise ValueError("Tentative d'accès non autorisée (Path Traversal)")
    return final_path


def handle_file_upload(conn, user_base_dir):
    relative_path = recv_prefixed_string(conn)
    filesize = struct.unpack('!Q', conn.recv(8))[0]
    print(f"    -> UPLOAD de '{relative_path}'...")
    try:
        full_path = safe_join(user_base_dir, relative_path)
        # Si un fichier existe déjà, on le versionne avant d'écraser
        if os.path.isfile(full_path):
            ts = datetime.now().strftime('%Y%m%d-%H%M%S')
            versions_dir = safe_join(user_base_dir, os.path.join('.versions', relative_path))
            os.makedirs(versions_dir, exist_ok=True)
            backup_path = os.path.join(versions_dir, f"{ts}.enc")
            try:
                os.replace(full_path, backup_path)
                print(f"    -> Version précédente sauvegardée: {backup_path}")

                # Si c'est un .enc, versionner aussi le .key correspondant (système X25519)
                if relative_path.endswith('.enc'):
                    key_relative_path = relative_path.replace('.enc', '.key')
                    key_full_path = safe_join(user_base_dir, key_relative_path)
                    if os.path.isfile(key_full_path):
                        key_versions_dir = safe_join(user_base_dir, os.path.join('.versions', key_relative_path))
                        os.makedirs(key_versions_dir, exist_ok=True)
                        key_backup_path = os.path.join(key_versions_dir, f"{ts}.key")
                        os.replace(key_full_path, key_backup_path)
                        print(f"    -> Version .key sauvegardée: {key_backup_path}")

            except Exception as e:
                print(f"    -> [VERSIONNING] Impossible de sauvegarder l'ancienne version: {e}")
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, 'wb') as f:
            received = 0
            while received < filesize:
                remaining = filesize - received
                chunk = conn.recv(min(4096, remaining))  # Ne pas lire plus que nécessaire !
                f.write(chunk)
                received += len(chunk)
        print(f"    -> '{relative_path}' sauvegardé.")
    except ValueError as e:
        print(f"    -> [SÉCURITÉ] {e}")


def handle_list_files(conn, user_base_dir, username, admin_username, storage_directory):
    print(f"    -> LIST demandé.")
    all_files = []
    for root, _, files in os.walk(user_base_dir):
        for name in files:
            full_path = os.path.join(root, name)
            # Pour l'admin, on veut le chemin complet depuis 'storage' (ex: user/fichier.txt)
            # Pour un user, on veut le chemin depuis son dossier (ex: fichier.txt)
            relative_path_base = storage_directory if username == admin_username else user_base_dir
            relative_path = os.path.relpath(full_path, relative_path_base)
            all_files.append(relative_path)

    file_list_bytes = "\n".join(sorted(all_files)).encode('utf-8')
    conn.sendall(struct.pack('!I', len(file_list_bytes)))
    conn.sendall(file_list_bytes)


def handle_file_download(conn, user_base_dir):
    relative_path = recv_prefixed_string(conn)
    print(f"    -> GET pour '{relative_path}'.")
    try:
        file_path = safe_join(user_base_dir, relative_path)
        if os.path.isfile(file_path):
            filesize = os.path.getsize(file_path)
            conn.sendall(struct.pack('!Q', filesize))
            with open(file_path, 'rb') as f:
                while chunk := f.read(4096): conn.sendall(chunk)
        else:
            conn.sendall(struct.pack('!Q', 0))
    except ValueError as e:
        print(f"    -> [SÉCURITÉ] {e}"); conn.sendall(struct.pack('!Q', 0))


def handle_list_versions(conn, user_base_dir):
    enc_relative_path = recv_prefixed_string(conn)
    print(f"    -> VERSIONS pour '{enc_relative_path}'.")
    try:
        versions_dir = safe_join(user_base_dir, os.path.join('.versions', enc_relative_path))
        versions = []
        if os.path.isdir(versions_dir):
            for name in os.listdir(versions_dir):
                if name.endswith('.enc'):
                    versions.append(name[:-4])  # retirer .enc
        versions_bytes = "\n".join(sorted(versions)).encode('utf-8')
        conn.sendall(struct.pack('!I', len(versions_bytes)))
        conn.sendall(versions_bytes)
    except ValueError as e:
        print(f"    -> [SÉCURITÉ] {e}")
        conn.sendall(struct.pack('!I', 0))


def handle_restore_version(conn, user_base_dir):
    enc_relative_path = recv_prefixed_string(conn)
    version_name = recv_prefixed_string(conn)
    print(f"    -> RESTORE '{enc_relative_path}' version '{version_name}'.")
    try:
        src_version_path = safe_join(user_base_dir, os.path.join('.versions', enc_relative_path, f"{version_name}.enc"))
        dst_current_path = safe_join(user_base_dir, enc_relative_path)

        # Sauvegarder l'actuel en version si présent
        if os.path.isfile(dst_current_path):
            ts = datetime.now().strftime('%Y%m%d-%H%M%S')
            versions_dir = safe_join(user_base_dir, os.path.join('.versions', enc_relative_path))
            os.makedirs(versions_dir, exist_ok=True)
            backup_path = os.path.join(versions_dir, f"{ts}.enc")
            try:
                os.replace(dst_current_path, backup_path)
                print(f"    -> Version actuelle sauvegardée: {backup_path}")

                # Si c'est un .enc, sauvegarder aussi le .key actuel (système X25519)
                if enc_relative_path.endswith('.enc'):
                    key_relative_path = enc_relative_path.replace('.enc', '.key')
                    key_current_path = safe_join(user_base_dir, key_relative_path)
                    if os.path.isfile(key_current_path):
                        key_versions_dir = safe_join(user_base_dir, os.path.join('.versions', key_relative_path))
                        os.makedirs(key_versions_dir, exist_ok=True)
                        key_backup_path = os.path.join(key_versions_dir, f"{ts}.key")
                        os.replace(key_current_path, key_backup_path)
                        print(f"    -> Version .key actuelle sauvegardée: {key_backup_path}")

            except Exception as e:
                print(f"    -> [VERSIONNING] Sauvegarde actuelle échouée: {e}")

        # Restaurer la version demandée (.enc)
        os.makedirs(os.path.dirname(dst_current_path), exist_ok=True)
        os.replace(src_version_path, dst_current_path)
        print(f"    -> Version .enc restaurée: {enc_relative_path}")

        # Si c'est un .enc, restaurer aussi le .key correspondant (système X25519)
        if enc_relative_path.endswith('.enc'):
            key_relative_path = enc_relative_path.replace('.enc', '.key')
            src_key_version_path = safe_join(user_base_dir, os.path.join('.versions', key_relative_path, f"{version_name}.key"))
            dst_key_current_path = safe_join(user_base_dir, key_relative_path)
            if os.path.isfile(src_key_version_path):
                os.replace(src_key_version_path, dst_key_current_path)
                print(f"    -> Version .key restaurée: {key_relative_path}")
            else:
                print(f"    -> [WARNING] Pas de version .key trouvée pour {version_name}")

        # Accusé de réception simple
        ack = "OK".encode('utf-8')
        conn.sendall(struct.pack('!I', len(ack)))
        conn.sendall(ack)
    except Exception as e:
        print(f"    -> [RESTORE] Erreur: {e}")
        msg = f"ERR: {e}".encode('utf-8')
        conn.sendall(struct.pack('!I', len(msg)))
        conn.sendall(msg)


def handle_delete_file(conn, user_base_dir, username, admin_username):
    # Tous les utilisateurs peuvent supprimer leurs propres fichiers
    rel_path = recv_prefixed_string(conn)
    print(f"    -> DELETE FILE '{rel_path}' par '{username}'.")
    try:
        target = safe_join(user_base_dir, rel_path)
        if os.path.isfile(target):
            os.remove(target)
            print(f"    -> '{rel_path}' supprimé.")

            # Supprimer aussi le fichier .key si c'est un .enc (système X25519)
            if rel_path.endswith('.enc'):
                key_path = rel_path.replace('.enc', '.key')
                target_key = safe_join(user_base_dir, key_path)
                if os.path.isfile(target_key):
                    os.remove(target_key)
                    print(f"    -> '{key_path}' supprimé également.")

            # Supprimer aussi les versions associées si elles existent
            versions_dir = safe_join(user_base_dir, os.path.join('.versions', rel_path))
            if os.path.isdir(versions_dir):
                import shutil
                shutil.rmtree(versions_dir)
                print(f"    -> Versions de '{rel_path}' supprimées.")

            # Supprimer les versions du .key aussi
            if rel_path.endswith('.enc'):
                key_path = rel_path.replace('.enc', '.key')
                versions_key_dir = safe_join(user_base_dir, os.path.join('.versions', key_path))
                if os.path.isdir(versions_key_dir):
                    import shutil
                    shutil.rmtree(versions_key_dir)
                    print(f"    -> Versions de '{key_path}' supprimées.")

            ack = "OK".encode('utf-8')
        else:
            ack = "ERR: not found".encode('utf-8')
        conn.sendall(struct.pack('!I', len(ack)))
        conn.sendall(ack)
    except Exception as e:
        msg = f"ERR: {e}".encode('utf-8')
        conn.sendall(struct.pack('!I', len(msg)))
        conn.sendall(msg)


def handle_delete_folder(conn, user_base_dir, username, admin_username):
    # Tous les utilisateurs peuvent supprimer leurs propres dossiers
    import shutil
    rel_path = recv_prefixed_string(conn)
    print(f"    -> DELETE FOLDER '{rel_path}' par '{username}'.")

    try:
        target = safe_join(user_base_dir, rel_path)

        if os.path.isdir(target):
            shutil.rmtree(target)
            print(f"    -> Dossier supprimé: {target}")

            # Supprimer aussi les versions associées si elles existent
            versions_dir = safe_join(user_base_dir, os.path.join('.versions', rel_path))
            if os.path.isdir(versions_dir):
                shutil.rmtree(versions_dir)

            ack = "OK".encode('utf-8')
        else:
            ack = "ERR: dossier non trouvé".encode('utf-8')
            print(f"    -> Dossier non trouvé: {target}")

        conn.sendall(struct.pack('!I', len(ack)))
        conn.sendall(ack)

    except Exception as e:
        print(f"    -> Erreur: {e}")
        msg = f"ERR: {str(e)[:100]}".encode('utf-8')
        conn.sendall(struct.pack('!I', len(msg)))
        conn.sendall(msg)


def handle_delete_version(conn, user_base_dir, username, admin_username):
    # Suppression réservée à l'admin
    if username != admin_username:
        msg = "FORBIDDEN".encode('utf-8')
        conn.sendall(struct.pack('!I', len(msg)))
        conn.sendall(msg)
        return

    enc_relative_path = recv_prefixed_string(conn)
    version_name = recv_prefixed_string(conn)
    print(f"    -> DELETE VERSION '{enc_relative_path}' version '{version_name}'.")
    try:
        target = safe_join(user_base_dir, os.path.join('.versions', enc_relative_path, f"{version_name}.enc"))
        if os.path.isfile(target):
            os.remove(target)
            ack = "OK".encode('utf-8')
        else:
            ack = "ERR: not found".encode('utf-8')
        conn.sendall(struct.pack('!I', len(ack)))
        conn.sendall(ack)
    except Exception as e:
        msg = f"ERR: {e}".encode('utf-8')
        conn.sendall(struct.pack('!I', len(msg)))
        conn.sendall(msg)


def handle_pubkey_upload(conn, user_base_dir):
    """
    Gère l'upload de la clé publique X25519 d'un utilisateur.
    Le serveur stocke uniquement les clés publiques (zero-knowledge).
    """
    print(f"    -> UPLOAD PUBLIC KEY")
    try:
        # Recevoir la taille de la clé publique
        pubkey_size = struct.unpack('!I', conn.recv(4))[0]

        # Recevoir la clé publique
        pubkey_data = b''
        while len(pubkey_data) < pubkey_size:
            chunk = conn.recv(min(4096, pubkey_size - len(pubkey_data)))
            if not chunk:
                break
            pubkey_data += chunk

        # Sauvegarder la clé publique
        pubkey_path = os.path.join(user_base_dir, 'public_key.pem')
        with open(pubkey_path, 'wb') as f:
            f.write(pubkey_data)

        print(f"    -> Clé publique sauvegardée: {pubkey_path}")

        # Accusé de réception
        ack = "OK".encode('utf-8')
        conn.sendall(struct.pack('!I', len(ack)))
        conn.sendall(ack)

    except Exception as e:
        print(f"    -> [PUBKEY UPLOAD] Erreur: {e}")
        msg = f"ERR: {e}".encode('utf-8')
        conn.sendall(struct.pack('!I', len(msg)))
        conn.sendall(msg)


def handle_pubkey_download(conn, user_base_dir):
    """
    Permet de récupérer la clé publique d'un utilisateur.
    Utile pour partager des fichiers entre utilisateurs.
    """
    print(f"    -> GET PUBLIC KEY")
    try:
        pubkey_path = os.path.join(user_base_dir, 'public_key.pem')

        if os.path.isfile(pubkey_path):
            pubkey_size = os.path.getsize(pubkey_path)
            conn.sendall(struct.pack('!I', pubkey_size))

            with open(pubkey_path, 'rb') as f:
                while chunk := f.read(4096):
                    conn.sendall(chunk)
        else:
            # Clé publique non trouvée
            conn.sendall(struct.pack('!I', 0))

    except Exception as e:
        print(f"    -> [PUBKEY DOWNLOAD] Erreur: {e}")
        conn.sendall(struct.pack('!I', 0))


if __name__ == "__main__":
    start_server()