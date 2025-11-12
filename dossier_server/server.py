# dossier_server/server.py
import socket
import os
import struct
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
            message_type = conn.recv(1)
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
            elif message_type == b'L':
                handle_list_files(conn, user_base_dir, username, admin_username, storage_directory)
            elif message_type == b'G':
                handle_file_download(conn, user_base_dir)

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
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, 'wb') as f:
            received = 0
            while received < filesize:
                chunk = conn.recv(4096);
                f.write(chunk);
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


if __name__ == "__main__":
    start_server()