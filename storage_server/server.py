# storage_server/server.py
import socket
import os
import struct
from datetime import datetime
from dotenv import load_dotenv


def start_server(host='0.0.0.0', port=65432):
    load_dotenv()
    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
    storage_directory = os.path.abspath("storage")
    if not os.path.exists(storage_directory): os.makedirs(storage_directory)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()
    print(f"Multi-user server started. Admin='{ADMIN_USERNAME}'. Listening on {host}:{port}")

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
    print(f"\n[CONNECTION] Received from {addr}")
    try:
        while True:
            print(f"  [SERVER] Waiting for command...")
            message_type = conn.recv(1)
            print(f"  [SERVER] Command received: {message_type}")
            if not message_type or message_type == b'E':
                if message_type == b'E': print("Client finished transmission.")
                break

            username = recv_prefixed_string(conn)
            if not username: break
            print(f"  -> Request from user '{username}'")

            user_base_dir = storage_directory if username == admin_username else os.path.join(storage_directory,
                                                                                              username)
            os.makedirs(user_base_dir, exist_ok=True)

            if message_type == b'F':
                handle_file_upload(conn, user_base_dir)
            elif message_type == b'K':
                handle_pubkey_upload(conn, user_base_dir)
            elif message_type == b'P':
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
        print(f"Error with {addr}: {e}")
    finally:
        print(f"[CONNECTION CLOSED] for {addr}"); conn.close()


def safe_join(base, path):
    """Prevents path traversal attacks by validating file paths"""
    final_path = os.path.abspath(os.path.join(base, path))
    if os.path.commonprefix([final_path, base]) != base:
        raise ValueError("Unauthorized access attempt (Path Traversal)")
    return final_path


def handle_file_upload(conn, user_base_dir):
    relative_path = recv_prefixed_string(conn)
    filesize = struct.unpack('!Q', conn.recv(8))[0]
    print(f"    -> UPLOAD '{relative_path}'...")
    try:
        full_path = safe_join(user_base_dir, relative_path)
        # Version existing file before overwriting
        if os.path.isfile(full_path):
            ts = datetime.now().strftime('%Y%m%d-%H%M%S')
            versions_dir = safe_join(user_base_dir, os.path.join('.versions', relative_path))
            os.makedirs(versions_dir, exist_ok=True)
            backup_path = os.path.join(versions_dir, f"{ts}.enc")
            try:
                os.replace(full_path, backup_path)
                print(f"    -> Previous version saved: {backup_path}")

                # Also version corresponding .key file (X25519 system)
                if relative_path.endswith('.enc'):
                    key_relative_path = relative_path.replace('.enc', '.key')
                    key_full_path = safe_join(user_base_dir, key_relative_path)
                    if os.path.isfile(key_full_path):
                        key_versions_dir = safe_join(user_base_dir, os.path.join('.versions', key_relative_path))
                        os.makedirs(key_versions_dir, exist_ok=True)
                        key_backup_path = os.path.join(key_versions_dir, f"{ts}.key")
                        os.replace(key_full_path, key_backup_path)
                        print(f"    -> .key version saved: {key_backup_path}")

            except Exception as e:
                print(f"    -> [VERSIONING] Failed to save old version: {e}")
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, 'wb') as f:
            received = 0
            while received < filesize:
                remaining = filesize - received
                chunk = conn.recv(min(4096, remaining))
                f.write(chunk)
                received += len(chunk)
        print(f"    -> '{relative_path}' saved.")
    except ValueError as e:
        print(f"    -> [SECURITY] {e}")


def handle_list_files(conn, user_base_dir, username, admin_username, storage_directory):
    print(f"    -> LIST requested.")
    all_files = []
    for root, _, files in os.walk(user_base_dir):
        for name in files:
            full_path = os.path.join(root, name)
            # Admin: full path from 'storage' (e.g., user/file.txt)
            # User: path from their folder (e.g., file.txt)
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
        print(f"    -> [SECURITY] {e}"); conn.sendall(struct.pack('!Q', 0))


def handle_list_versions(conn, user_base_dir):
    enc_relative_path = recv_prefixed_string(conn)
    print(f"    -> VERSIONS for '{enc_relative_path}'.")
    try:
        versions_dir = safe_join(user_base_dir, os.path.join('.versions', enc_relative_path))
        versions = []
        if os.path.isdir(versions_dir):
            for name in os.listdir(versions_dir):
                if name.endswith('.enc'):
                    versions.append(name[:-4])
        versions_bytes = "\n".join(sorted(versions)).encode('utf-8')
        conn.sendall(struct.pack('!I', len(versions_bytes)))
        conn.sendall(versions_bytes)
    except ValueError as e:
        print(f"    -> [SECURITY] {e}")
        conn.sendall(struct.pack('!I', 0))


def handle_restore_version(conn, user_base_dir):
    enc_relative_path = recv_prefixed_string(conn)
    version_name = recv_prefixed_string(conn)
    print(f"    -> RESTORE '{enc_relative_path}' version '{version_name}'.")
    try:
        src_version_path = safe_join(user_base_dir, os.path.join('.versions', enc_relative_path, f"{version_name}.enc"))
        dst_current_path = safe_join(user_base_dir, enc_relative_path)

        # Save current as version if present
        if os.path.isfile(dst_current_path):
            ts = datetime.now().strftime('%Y%m%d-%H%M%S')
            versions_dir = safe_join(user_base_dir, os.path.join('.versions', enc_relative_path))
            os.makedirs(versions_dir, exist_ok=True)
            backup_path = os.path.join(versions_dir, f"{ts}.enc")
            try:
                os.replace(dst_current_path, backup_path)
                print(f"    -> Current version saved: {backup_path}")

                # Also save current .key (X25519 system)
                if enc_relative_path.endswith('.enc'):
                    key_relative_path = enc_relative_path.replace('.enc', '.key')
                    key_current_path = safe_join(user_base_dir, key_relative_path)
                    if os.path.isfile(key_current_path):
                        key_versions_dir = safe_join(user_base_dir, os.path.join('.versions', key_relative_path))
                        os.makedirs(key_versions_dir, exist_ok=True)
                        key_backup_path = os.path.join(key_versions_dir, f"{ts}.key")
                        os.replace(key_current_path, key_backup_path)
                        print(f"    -> Current .key version saved: {key_backup_path}")

            except Exception as e:
                print(f"    -> [VERSIONING] Failed to save current: {e}")

        # Restore requested version (.enc)
        os.makedirs(os.path.dirname(dst_current_path), exist_ok=True)
        os.replace(src_version_path, dst_current_path)
        print(f"    -> .enc version restored: {enc_relative_path}")

        # Also restore corresponding .key (X25519 system)
        if enc_relative_path.endswith('.enc'):
            key_relative_path = enc_relative_path.replace('.enc', '.key')
            src_key_version_path = safe_join(user_base_dir, os.path.join('.versions', key_relative_path, f"{version_name}.key"))
            dst_key_current_path = safe_join(user_base_dir, key_relative_path)
            if os.path.isfile(src_key_version_path):
                os.replace(src_key_version_path, dst_key_current_path)
                print(f"    -> .key version restored: {key_relative_path}")
            else:
                print(f"    -> [WARNING] No .key version found for {version_name}")

        ack = "OK".encode('utf-8')
        conn.sendall(struct.pack('!I', len(ack)))
        conn.sendall(ack)
    except Exception as e:
        print(f"    -> [RESTORE] Error: {e}")
        msg = f"ERR: {e}".encode('utf-8')
        conn.sendall(struct.pack('!I', len(msg)))
        conn.sendall(msg)


def handle_delete_file(conn, user_base_dir, username, admin_username):
    rel_path = recv_prefixed_string(conn)
    print(f"    -> DELETE FILE '{rel_path}' by '{username}'.")
    try:
        target = safe_join(user_base_dir, rel_path)
        if os.path.isfile(target):
            os.remove(target)
            print(f"    -> '{rel_path}' deleted.")

            # Also delete .key file if this is a .enc (X25519 system)
            if rel_path.endswith('.enc'):
                key_path = rel_path.replace('.enc', '.key')
                target_key = safe_join(user_base_dir, key_path)
                if os.path.isfile(target_key):
                    os.remove(target_key)
                    print(f"    -> '{key_path}' also deleted.")

            # Delete associated versions if they exist
            versions_dir = safe_join(user_base_dir, os.path.join('.versions', rel_path))
            if os.path.isdir(versions_dir):
                import shutil
                shutil.rmtree(versions_dir)
                print(f"    -> Versions of '{rel_path}' deleted.")

            # Delete .key versions too
            if rel_path.endswith('.enc'):
                key_path = rel_path.replace('.enc', '.key')
                versions_key_dir = safe_join(user_base_dir, os.path.join('.versions', key_path))
                if os.path.isdir(versions_key_dir):
                    import shutil
                    shutil.rmtree(versions_key_dir)
                    print(f"    -> Versions of '{key_path}' deleted.")

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
    import shutil
    rel_path = recv_prefixed_string(conn)
    print(f"    -> DELETE FOLDER '{rel_path}' by '{username}'.")

    try:
        target = safe_join(user_base_dir, rel_path)

        if os.path.isdir(target):
            shutil.rmtree(target)
            print(f"    -> Folder deleted: {target}")

            # Delete associated versions if they exist
            versions_dir = safe_join(user_base_dir, os.path.join('.versions', rel_path))
            if os.path.isdir(versions_dir):
                shutil.rmtree(versions_dir)

            ack = "OK".encode('utf-8')
        else:
            ack = "ERR: folder not found".encode('utf-8')
            print(f"    -> Folder not found: {target}")

        conn.sendall(struct.pack('!I', len(ack)))
        conn.sendall(ack)

    except Exception as e:
        print(f"    -> Error: {e}")
        msg = f"ERR: {str(e)[:100]}".encode('utf-8')
        conn.sendall(struct.pack('!I', len(msg)))
        conn.sendall(msg)


def handle_delete_version(conn, user_base_dir, username, admin_username):
    """Admin-only: delete specific file versions"""
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
    Handles upload of user's X25519 public key.
    Server stores only public keys (zero-knowledge).
    """
    print(f"    -> UPLOAD PUBLIC KEY")
    try:
        pubkey_size = struct.unpack('!I', conn.recv(4))[0]

        pubkey_data = b''
        while len(pubkey_data) < pubkey_size:
            chunk = conn.recv(min(4096, pubkey_size - len(pubkey_data)))
            if not chunk:
                break
            pubkey_data += chunk

        pubkey_path = os.path.join(user_base_dir, 'public_key.pem')
        with open(pubkey_path, 'wb') as f:
            f.write(pubkey_data)

        print(f"    -> Public key saved: {pubkey_path}")

        ack = "OK".encode('utf-8')
        conn.sendall(struct.pack('!I', len(ack)))
        conn.sendall(ack)

    except Exception as e:
        print(f"    -> [PUBKEY UPLOAD] Error: {e}")
        msg = f"ERR: {e}".encode('utf-8')
        conn.sendall(struct.pack('!I', len(msg)))
        conn.sendall(msg)


def handle_pubkey_download(conn, user_base_dir):
    """
    Retrieves user's public key.
    Useful for sharing files between users.
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
            conn.sendall(struct.pack('!I', 0))

    except Exception as e:
        print(f"    -> [PUBKEY DOWNLOAD] Error: {e}")
        conn.sendall(struct.pack('!I', 0))


if __name__ == "__main__":
    start_server()