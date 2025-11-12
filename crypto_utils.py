# crypto_utils.py
from Crypto.Cipher import AES
import os

# La clé est partagée par le client et le serveur.
# Pour une sécurité maximale, chargez-la depuis une variable d'environnement.
# ATTENTION : La clé doit faire 16, 24 ou 32 octets. "Zb3ul_ProjetAES!" fait 16 octets, c'est bon.
KEY = b"Zb3ul_ProjetAES!"




def chiffrer_fichier(path_in, path_out):
    """
    Chiffre un fichier (path_in) et sauvegarde le résultat chiffré (path_out).
    Retourne True en cas de succès, False en cas d'échec.
    """
    try:
        with open(path_in, "rb") as f:
            data = f.read()

        cipher = AES.new(KEY, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        with open(path_out, "wb") as f:
            # On écrit le nonce (valeur aléatoire), le tag (authentification), puis le contenu chiffré
            [f.write(x) for x in (cipher.nonce, tag, ciphertext)]

        # Décommenter la ligne ci-dessous si vous voulez voir les logs de chiffrement
        # print(f"[✔] Fichier chiffré : {path_out}")
        return True
    except Exception as e:
        print(f"[❌] Erreur critique lors du chiffrement de {path_in}: {e}")
        return False


def dechiffrer_fichier(path_in, path_out):
    """
    Déchiffre un fichier (path_in) et sauvegarde le résultat en clair (path_out).
    Retourne True en cas de succès, False en cas d'échec.
    """
    try:
        with open(path_in, "rb") as f:
            # On lit les 3 parties du fichier chiffré dans le bon ordre
            nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]

        cipher = AES.new(KEY, AES.MODE_EAX, nonce=nonce)

        # Cette ligne déchiffre ET vérifie que le fichier n'a pas été modifié (grâce au tag)
        data = cipher.decrypt_and_verify(ciphertext, tag)

        with open(path_out, "wb") as f:
            f.write(data)

        # Décommenter la ligne ci-dessous si vous voulez voir les logs de déchiffrement
        # print(f"[🔓] Fichier déchiffré : {path_out}")
        return True
    except Exception as e:
        print(f"[❌] Erreur critique lors du déchiffrement de {path_in}: {e}. (Fichier corrompu ou mauvaise clé ?)")
        return False