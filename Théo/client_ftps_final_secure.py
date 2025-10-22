import ssl, socket, os
from ftplib import FTP
from Crypto.Cipher import AES

IP = "127.0.0.1"
PORT = 2121
USER = "user"
MDP = "12345"
KEY = b"Zb3ul_ProjetAES!"  # même clé que sur le serveur

def connexion_ftps_implicite():
    """Connexion SSL directe (FTPS implicite)"""
    context = ssl._create_unverified_context()
    sock = socket.create_connection((IP, PORT))
    ssock = context.wrap_socket(sock)
    ftp = FTP()
    ftp.sock = ssock          # ⚠️ on met directement le socket SSL
    ftp.af = socket.AF_INET   # ✅ évite le blocage et l'erreur AttributeError
    ftp.file = ssock.makefile('r')
    ftp.welcome = ftp.getresp()
    ftp.login(USER, MDP)
    print("🔐 Connexion FTPS implicite établie.")
    return ftp


def dechiffrer_fichier(path):
    with open(path, "rb") as f:
        nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]
    cipher = AES.new(KEY, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    out = path.replace(".enc", "")
    with open(out, "wb") as f:
        f.write(data)
    os.remove(path)  # ✅ supprime le fichier .enc après déchiffrement
    print(f"🔓 Fichier déchiffré : {out}")


def sauvegarder(dossier):
    ftp = connexion_ftps_implicite()
    for root, _, files in os.walk(dossier):
        for file in files:
            path = os.path.join(root, file)
            with open(path, "rb") as f:
                print(f"⬆️ Envoi de {file} ...")
                ftp.storbinary(f"STOR {file}", f)
    ftp.quit()
    print("✅ Sauvegarde terminée.")

def restaurer():
    ftp = connexion_ftps_implicite()
    fichiers = ftp.nlst()
    for f in fichiers:
        if f.endswith(".enc"):
            print(f"⬇️ Téléchargement de {f} ...")
            with open(f, "wb") as local_file:
                ftp.retrbinary(f"RETR " + f, local_file.write)
            dechiffrer_fichier(f)
    ftp.quit()
    print("✅ Restauration + déchiffrement terminées.")

if __name__ == "__main__":
    print("=== Outil de sauvegarde FTPS sécurisé ===")
    print("1. Sauvegarder un dossier")
    print("2. Restaurer + Télécharger + Déchiffrer automatiquement")
    choix = input("Choix : ")
    if choix == "1":
        dossier = input("Dossier à sauvegarder : ")
        sauvegarder(dossier)
    elif choix == "2":
        restaurer()

