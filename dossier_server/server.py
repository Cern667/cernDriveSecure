import socket
import os
import struct


def start_server(host='0.0.0.0', port=65432):
    storage_directory = "storage"
    if not os.path.exists(storage_directory): os.makedirs(storage_directory)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()
    print(f"✅ Serveur de Stockage démarré. En écoute sur {host}:{port}")

    while True:
        try:
            conn, addr = server_socket.accept()
            handle_client(conn, addr, storage_directory)
        except KeyboardInterrupt:
            print("\nArrêt du serveur.");
            break
    server_socket.close()


def handle_client(conn, addr, storage_directory):
    print(f"\n[CONNEXION] Reçue de {addr}")
    try:
        while True:
            message_type = conn.recv(1)
            if not message_type or message_type == b'E':
                if message_type == b'E': print("✅ Le client a terminé la transmission.")
                break

            if message_type == b'F':  # UPLOAD un Fichier
                handle_file_upload(conn, storage_directory)

            elif message_type == b'L':  # NOUVEAU: LISTER les fichiers
                print("  -> Demande de la liste des fichiers reçue.")
                files = os.listdir(storage_directory)
                file_list_bytes = "\n".join(files).encode('utf-8')
                # Envoyer la taille de la liste, puis la liste
                conn.sendall(struct.pack('!I', len(file_list_bytes)))
                conn.sendall(file_list_bytes)
                print(f"  -> Liste de {len(files)} fichiers envoyée.")

            elif message_type == b'G':  # NOUVEAU: GET un fichier (Download)
                handle_file_download(conn, storage_directory)

    except Exception as e:
        print(f"❌ Une erreur est survenue avec {addr}: {e}")
    finally:
        print(f"[CONNEXION FERMÉE] pour {addr}")
        conn.close()


def handle_file_upload(conn, storage_directory):
    filename_len = struct.unpack('!I', conn.recv(4))[0]
    filename = conn.recv(filename_len).decode('utf-8')
    filesize = struct.unpack('!Q', conn.recv(8))[0]
    print(f"  -> Réception de '{filename}' ({filesize} octets)")
    file_path = os.path.join(storage_directory, os.path.basename(filename))
    with open(file_path, 'wb') as f:
        received = 0
        while received < filesize:
            chunk = conn.recv(4096);
            f.write(chunk);
            received += len(chunk)
    print(f"  -> '{filename}' sauvegardé avec succès.")


def handle_file_download(conn, storage_directory):
    filename_len = struct.unpack('!I', conn.recv(4))[0]
    filename = conn.recv(filename_len).decode('utf-8')
    print(f"  -> Demande de téléchargement pour '{filename}' reçue.")
    file_path = os.path.join(storage_directory, filename)
    if os.path.isfile(file_path):
        filesize = os.path.getsize(file_path)
        conn.sendall(struct.pack('!Q', filesize))
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                conn.sendall(chunk)
        print(f"  -> '{filename}' envoyé avec succès.")
    else:
        print(f"  -> Fichier '{filename}' non trouvé. Envoi d'une taille de 0.")
        conn.sendall(struct.pack('!Q', 0))  # Envoyer 0 pour indiquer que le fichier n'existe pas


if __name__ == "__main__":
    start_server()