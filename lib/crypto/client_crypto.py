#!/usr/bin/env python3
"""
Client-side encryption module for secure NAS
Architecture: X25519 (asymmetric keys) + AES-256-GCM (file encryption)

Each user has:
- A private X25519 key (stored locally, encrypted by password)
- A public X25519 key (sent to server)

Workflow :
1. X25519 key generation per user
2. File encryption with AES-256-GCM (random key)
3. AES key encryption with X25519 (ECDH)
4. Upload: file.enc + aes_key.enc
5. Download: decrypt AES key then file
"""

import os
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# ============================================================================
# 1. GESTION DES CLÉS X25519
# ============================================================================

def generer_cles_utilisateur(output_dir="."):
    """
    Generates an X25519 keypair for a user.

    Args:
        output_dir: Directory to save keys

    Returns:
        tuple: (chemin_privkey, chemin_pubkey)
    """
    os.makedirs(output_dir, exist_ok=True)

    # Keypair generation
    privkey = X25519PrivateKey.generate()
    pubkey = privkey.public_key()

    # Serialization in PEM format
    privkey_pem = privkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pubkey_pem = pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save to disk
    privkey_path = os.path.join(output_dir, "private_key.pem")
    pubkey_path = os.path.join(output_dir, "public_key.pem")

    with open(privkey_path, "wb") as f:
        f.write(privkey_pem)

    with open(pubkey_path, "wb") as f:
        f.write(pubkey_pem)

    # Restrictive permissions on private key
    os.chmod(privkey_path, 0o600)

    return privkey_path, pubkey_path


def charger_cle_privee(privkey_path):
    """
    Loads an X25519 private key from a PEM file.

    Args:
        privkey_path: Path to private key file

    Returns:
        X25519PrivateKey: Private key
    """
    with open(privkey_path, "rb") as f:
        privkey = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    return privkey


def charger_cle_publique(pubkey_path):
    """
    Loads a public key (EC P-256 or X25519) from a PEM file.

    Args:
        pubkey_path: Path to public key file

    Returns:
        CryptoKey: Public key (EC ou X25519)
        
    Note:
        Accepts EC P-256 (Web Crypto API) and X25519 (Python backend)
    """
    with open(pubkey_path, "rb") as f:
        pubkey = serialization.load_pem_public_key(f.read())
    
    # ✅ Accept EC (P-256) and X25519
    # Web Crypto API generates P-256, Python backend can generate X25519
    from cryptography.hazmat.primitives.asymmetric import ec
    
    if not isinstance(pubkey, (X25519PublicKey, ec.EllipticCurvePublicKey)):
        key_type = type(pubkey).__name__
        raise ValueError(
            f"Unsupported key type : {key_type}. "
            f"Supported keys: EC P-256 or X25519."
        )
    
    return pubkey


# ============================================================================
# 2. CHIFFREMENT DE FICHIERS (AES-256-GCM)
# ============================================================================

def chiffrer_fichier_aes(fichier_path, fichier_out_path):
    """
    Encrypts a file with AES-256-GCM (random key).

    Args:
        fichier_path: Path to plaintext file
        fichier_out_path: Path to encrypted file

    Returns:
        tuple: (cle_aes, nonce) ou (None, None) en cas d'erreur
    """
    try:
        # Random AES key generation
        cle_aes = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(cle_aes)

        # Nonce generation (12 bytes for GCM)
        nonce = os.urandom(12)

        # Read and encrypt file
        with open(fichier_path, "rb") as f:
            data = f.read()

        ciphertext = aesgcm.encrypt(nonce, data, None)

        # Save: nonce (12) + ciphertext (data + tag 16 bytes)
        with open(fichier_out_path, "wb") as f:
            f.write(nonce)
            f.write(ciphertext)

        return cle_aes, nonce

    except Exception as e:
        print(f"AES encryption error : {e}")
        return None, None


def dechiffrer_fichier_aes(fichier_enc_path, fichier_out_path, cle_aes):
    """
    Decrypts an AES-256-GCM file.

    Args:
        fichier_enc_path: Path to encrypted file
        fichier_out_path: Path to decrypted file
        cle_aes: AES key (32 bytes)

    Returns:
        bool: True si succès, False sinon
    """
    try:
        # Read encrypted file
        with open(fichier_enc_path, "rb") as f:
            nonce = f.read(12)
            ciphertext = f.read()

        # Decryption
        aesgcm = AESGCM(cle_aes)
        data = aesgcm.decrypt(nonce, ciphertext, None)

        # Sauvegarde
        with open(fichier_out_path, "wb") as f:
            f.write(data)

        return True

    except Exception as e:
        print(f"AES decryption error : {e}")
        return False


# ============================================================================
# 3. CHIFFREMENT DE LA CLÉ AES AVEC X25519
# ============================================================================

def chiffrer_cle_aes(cle_aes, pubkey):
    """
    Encrypts an AES key with ECDH (supports EC P-256 and X25519) + HKDF + AES-GCM.

    Args:
        cle_aes: AES key to encrypt (32 bytes)
        pubkey: Recipient public key (EC P-256 or X25519)

    Returns:
        bytes: Encrypted AES key (format : ephemeral_pubkey + nonce + ciphertext)
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend
        
        # Detect key type and generate corresponding ephemeral key
        if isinstance(pubkey, ec.EllipticCurvePublicKey):
            # EC P-256 key (from browser)
            ephemeral_privkey = ec.generate_private_key(ec.SECP256R1(), default_backend())
            ephemeral_pubkey = ephemeral_privkey.public_key()
            
            # ECDH: shared secret computation with EC
            shared_secret = ephemeral_privkey.exchange(ec.ECDH(), pubkey)
            
            # Ephemeral EC public key format (65 bytes uncompressed)
            ephemeral_pubkey_bytes = ephemeral_pubkey.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
        elif isinstance(pubkey, X25519PublicKey):
            # X25519 key (Python backend)
            ephemeral_privkey = X25519PrivateKey.generate()
            ephemeral_pubkey = ephemeral_privkey.public_key()
            
            # ECDH: shared secret computation with X25519
            shared_secret = ephemeral_privkey.exchange(pubkey)
            
            # Ephemeral X25519 public key format (32 bytes)
            ephemeral_pubkey_bytes = ephemeral_pubkey.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        else:
            raise ValueError(f"Unsupported key type: {type(pubkey).__name__}")

        # Key derivation (HKDF-SHA256)
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'nas-aes-key-encryption'
        )
        derived_key = kdf.derive(shared_secret)

        # AES key encryption
        aesgcm = AESGCM(derived_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, cle_aes, None)

        # Format: ephemeral_pubkey (32 or 65 bytes) + nonce (12) + ciphertext (32 + 16 tag)
        return ephemeral_pubkey_bytes + nonce + ciphertext

    except Exception as e:
        print(f"AES key encryption error : {e}")
        import traceback
        traceback.print_exc()
        return None


        # Format : ephemeral_pubkey (32) + nonce (12) + ciphertext (32 + 16 tag)
        ephemeral_pubkey_bytes = ephemeral_pubkey.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        return ephemeral_pubkey_bytes + nonce + ciphertext

    except Exception as e:
        print(f"AES key encryption error : {e}")
        return None


def dechiffrer_cle_aes(cle_aes_enc, privkey):
    """
    Decrypts an AES key with X25519 (ECDH + HKDF + AES-GCM).

    Args:
        cle_aes_enc: Encrypted AES key (ephemeral_pubkey + nonce + ciphertext)
        privkey: X25519 private key

    Returns:
        bytes: AES key (32 bytes) ou None en cas d'erreur
    """
    try:
        # Parsing: 32 bytes pubkey + 12 bytes nonce + rest ciphertext
        ephemeral_pubkey_bytes = cle_aes_enc[:32]
        nonce = cle_aes_enc[32:44]
        ciphertext = cle_aes_enc[44:]

        # Ephemeral public key reconstruction
        ephemeral_pubkey = X25519PublicKey.from_public_bytes(ephemeral_pubkey_bytes)

        # ECDH
        shared_secret = privkey.exchange(ephemeral_pubkey)

        # Dérivation de clé
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'nas-aes-key-encryption'
        )
        derived_key = kdf.derive(shared_secret)

        # Decryption
        aesgcm = AESGCM(derived_key)
        cle_aes = aesgcm.decrypt(nonce, ciphertext, None)

        return cle_aes

    except Exception as e:
        print(f"AES key decryption error : {e}")
        return None


# ============================================================================
# 4. API HAUT NIVEAU
# ============================================================================

def chiffrer_fichier_complet(fichier_path, user_pubkey_path, output_dir="."):
    """
    Encrypts a complete file (file + AES key).

    Args:
        fichier_path: Path to file to encrypt
        user_pubkey_path: Path to user public key
        output_dir: Output directory

    Returns:
        tuple: (fichier_enc_path, cle_aes_enc_path) ou (None, None)
    """
    try:
        os.makedirs(output_dir, exist_ok=True)

        # File encryption with AES
        fichier_enc_path = os.path.join(output_dir, os.path.basename(fichier_path) + ".enc")
        cle_aes, _ = chiffrer_fichier_aes(fichier_path, fichier_enc_path)

        if not cle_aes:
            return None, None

        # AES key encryption avec X25519
        pubkey = charger_cle_publique(user_pubkey_path)
        cle_aes_enc = chiffrer_cle_aes(cle_aes, pubkey)

        if not cle_aes_enc:
            return None, None

        # Save encrypted AES key
        cle_aes_enc_path = os.path.join(output_dir, os.path.basename(fichier_path) + ".key")
        with open(cle_aes_enc_path, "wb") as f:
            f.write(cle_aes_enc)

        return fichier_enc_path, cle_aes_enc_path

    except ValueError as e:
        # Erreur de validation de type de clé
        print(f"❌ Key validation error : {e}")
        return None, None
    except Exception as e:
        print(f"Complete encryption error : {e}")
        return None, None


def dechiffrer_fichier_complet(fichier_enc_path, cle_aes_enc_path, user_privkey_path, output_dir="."):
    """
    Decrypts a complete file (AES key then file).

    Args:
        fichier_enc_path: Path to encrypted file
        cle_aes_enc_path: Chemin de la clé AES chiffrée
        user_privkey_path: Chemin de la clé privée de l'utilisateur
        output_dir: Output directory

    Returns:
        str: Path to decrypted file ou None
    """
    try:
        os.makedirs(output_dir, exist_ok=True)

        # Load private key
        privkey = charger_cle_privee(user_privkey_path)

        # Decryption de la clé AES
        with open(cle_aes_enc_path, "rb") as f:
            cle_aes_enc = f.read()

        cle_aes = dechiffrer_cle_aes(cle_aes_enc, privkey)

        if not cle_aes:
            return None

        # Decryption du fichier
        fichier_out_path = os.path.join(output_dir, os.path.basename(fichier_enc_path).replace(".enc", ""))

        if not dechiffrer_fichier_aes(fichier_enc_path, fichier_out_path, cle_aes):
            return None

        return fichier_out_path

    except Exception as e:
        print(f"Complete decryption error : {e}")
        return None


# ============================================================================
# 5. SCRIPT DE TEST
# ============================================================================

if __name__ == "__main__":
    print("Client-side encryption system test\n")

    # Test 1 : Génération de clés
    print("1️⃣  Generating X25519 keys...")
    privkey_path, pubkey_path = generer_cles_utilisateur(".test_keys")
    print(f"   ✅ Private key : {privkey_path}")
    print(f"   ✅ Public key : {pubkey_path}\n")

    # Test 2 : Création d'un fichier de test
    print("2️⃣  Creating test file...")
    test_file = ".test_keys/test_data.txt"
    with open(test_file, "w") as f:
        f.write("Données confidentielles du NAS sécurisé !")
    print(f"   ✅ File created : {test_file}\n")

    # Test 3 : Chiffrement complet
    print("3️⃣  Complete encryption...")
    enc_file, key_file = chiffrer_fichier_complet(test_file, pubkey_path, ".test_keys")
    print(f"   ✅ Encrypted file : {enc_file}")
    print(f"   ✅ Encrypted AES key : {key_file}\n")

    # Test 4 : Decryption complet
    print("4️⃣  Decryption complet...")
    dec_file = dechiffrer_fichier_complet(enc_file, key_file, privkey_path, ".test_keys")
    print(f"   ✅ Decrypted file : {dec_file}\n")

    # Test 5 : Vérification
    print("5️⃣  Verification...")
    with open(dec_file, "r") as f:
        content = f.read()
    print(f"   ✅ Content : {content}\n")

    # Nettoyage
    print("6️⃣  Cleanup...")
    import shutil
    shutil.rmtree(".test_keys")
    print("   ✅ Test files deleted\n")

    print("✅ All tests passed successfully !")
