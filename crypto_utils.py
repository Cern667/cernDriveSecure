# crypto_utils.py
from Crypto.Cipher import AES
import os
import base64
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

def _get_encryption_key():
    """
    Récupère la clé de chiffrement depuis les variables d'environnement.
    Utilise une clé par défaut seulement si AES_ENCRYPTION_KEY n'est pas définie.

    Returns:
        bytes: Clé de chiffrement AES (16, 24 ou 32 octets)
    """
    # Tenter de récupérer la clé depuis l'environnement
    key_b64 = os.environ.get('AES_ENCRYPTION_KEY')

    if key_b64:
        try:
            # Décoder la clé base64
            key = base64.b64decode(key_b64)
            # Vérifier la taille
            if len(key) in [16, 24, 32]:
                return key
            else:
                print(f"⚠️  AVERTISSEMENT: La clé AES doit faire 16, 24 ou 32 octets (taille actuelle: {len(key)})")
        except Exception as e:
            print(f"⚠️  AVERTISSEMENT: Impossible de décoder AES_ENCRYPTION_KEY: {e}")

    # Clé par défaut (NON SÉCURISÉE - à utiliser uniquement pour le développement)
    print("⚠️  AVERTISSEMENT SÉCURITÉ: Utilisation de la clé par défaut!")
    print("⚠️  Générez une clé sécurisée avec: python generate_aes_key.py")
    return b"Zb3ul_ProjetAES!"

# Initialiser la clé au chargement du module
KEY = _get_encryption_key()




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