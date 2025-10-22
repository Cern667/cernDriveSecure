from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from pyftpdlib.log import config_logging
from Crypto.Cipher import AES
import os, ssl

KEY = b"Zb3ul_ProjetAES!" # 16 octets

def chiffrer_fichier(path):
    with open(path, "rb") as f:
        data = f.read()
    cipher = AES.new(KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    with open(path + ".enc", "wb") as f:
        for x in (cipher.nonce, tag, ciphertext):
            f.write(x)
    os.remove(path)
    print(f"[✔] Fichier reçu et chiffré : {path}.enc")

def dechiffrer_fichier(path):
    with open(path, "rb") as f:
        nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]
    cipher = AES.new(KEY, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    out = path.replace(".enc", "")
    with open(out, "wb") as f:
        f.write(data)
    return out

class SecureHandler(FTPHandler):
    def on_connect(self):
        print(f"[🔐] Connexion depuis {self.remote_ip}")

    def on_file_received(self, file):
        try:
            chiffrer_fichier(file)
        except Exception as e:
            print(f"[❌] Erreur chiffrement : {e}")

    def ftp_RESTORE(self, filename):
        path = os.path.join(self.cwd, filename)
        if not os.path.exists(path):
            self.respond("550 Fichier introuvable.")
            return
        try:
            out = dechiffrer_fichier(path)
            self.respond(f"200 Fichier déchiffré : {os.path.basename(out)}")
            print(f"[🔓] Fichier déchiffré : {out}")
        except Exception as e:
            self.respond("550 Erreur déchiffrement.")
            print(f"[❌] {e}")

# --- Configuration du serveur ---
base_dir = os.path.join(os.getcwd(), "sauvegardes")
os.makedirs(base_dir, exist_ok=True)

authorizer = DummyAuthorizer()
authorizer.add_user("user", "12345", base_dir, perm="elradfmwMT")

handler = SecureHandler
handler.authorizer = authorizer
handler.banner = "Serveur FTPS implicite prêt."

# --- SSL implicite ---
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

server = FTPServer(("0.0.0.0", 2121), handler)
server.socket = context.wrap_socket(server.socket, server_side=True)
config_logging(level="INFO")

print("🚀 Serveur FTPS implicite sécurisé en cours d'exécution sur le port 2121 ...")
server.serve_forever()

