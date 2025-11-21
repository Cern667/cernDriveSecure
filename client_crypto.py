#!/usr/bin/env python3
"""
Module de chiffrement côté client pour NAS sécurisé
Architecture : X25519 (clés asymétriques) + AES-256-GCM (chiffrement fichiers)

Chaque utilisateur possède :
- Une clé privée X25519 (stockée localement, chiffrée par mot de passe)
- Une clé publique X25519 (envoyée au serveur)

Workflow :
1. Génération de clés X25519 par utilisateur
2. Chiffrement fichier avec AES-256-GCM (clé aléatoire)
3. Chiffrement de la clé AES avec X25519 (ECDH)
4. Upload : fichier.enc + cle_aes.enc
5. Download : déchiffrement clé AES puis fichier
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
    Génère une paire de clés X25519 pour un utilisateur.

    Args:
        output_dir: Répertoire où sauvegarder les clés

    Returns:
        tuple: (chemin_privkey, chemin_pubkey)
    """
    os.makedirs(output_dir, exist_ok=True)

    # Génération de la paire de clés
    privkey = X25519PrivateKey.generate()
    pubkey = privkey.public_key()

    # Sérialisation en format PEM
    privkey_pem = privkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pubkey_pem = pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Sauvegarde sur disque
    privkey_path = os.path.join(output_dir, "private_key.pem")
    pubkey_path = os.path.join(output_dir, "public_key.pem")

    with open(privkey_path, "wb") as f:
        f.write(privkey_pem)

    with open(pubkey_path, "wb") as f:
        f.write(pubkey_pem)

    # Permissions restrictives sur la clé privée
    os.chmod(privkey_path, 0o600)

    return privkey_path, pubkey_path


def charger_cle_privee(privkey_path):
    """
    Charge une clé privée X25519 depuis un fichier PEM.

    Args:
        privkey_path: Chemin vers le fichier de clé privée

    Returns:
        X25519PrivateKey: Clé privée
    """
    with open(privkey_path, "rb") as f:
        privkey = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    return privkey


def charger_cle_publique(pubkey_path):
    """
    Charge une clé publique X25519 depuis un fichier PEM.

    Args:
        pubkey_path: Chemin vers le fichier de clé publique

    Returns:
        X25519PublicKey: Clé publique
    """
    with open(pubkey_path, "rb") as f:
        pubkey = serialization.load_pem_public_key(f.read())
    return pubkey


# ============================================================================
# 2. CHIFFREMENT DE FICHIERS (AES-256-GCM)
# ============================================================================

def chiffrer_fichier_aes(fichier_path, fichier_out_path):
    """
    Chiffre un fichier avec AES-256-GCM (clé aléatoire).

    Args:
        fichier_path: Chemin du fichier en clair
        fichier_out_path: Chemin du fichier chiffré

    Returns:
        tuple: (cle_aes, nonce) ou (None, None) en cas d'erreur
    """
    try:
        # Génération clé AES aléatoire
        cle_aes = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(cle_aes)

        # Génération nonce (12 bytes pour GCM)
        nonce = os.urandom(12)

        # Lecture et chiffrement du fichier
        with open(fichier_path, "rb") as f:
            data = f.read()

        ciphertext = aesgcm.encrypt(nonce, data, None)

        # Sauvegarde : nonce (12) + ciphertext (data + tag 16 bytes)
        with open(fichier_out_path, "wb") as f:
            f.write(nonce)
            f.write(ciphertext)

        return cle_aes, nonce

    except Exception as e:
        print(f"❌ Erreur chiffrement AES : {e}")
        return None, None


def dechiffrer_fichier_aes(fichier_enc_path, fichier_out_path, cle_aes):
    """
    Déchiffre un fichier AES-256-GCM.

    Args:
        fichier_enc_path: Chemin du fichier chiffré
        fichier_out_path: Chemin du fichier déchiffré
        cle_aes: Clé AES (32 bytes)

    Returns:
        bool: True si succès, False sinon
    """
    try:
        # Lecture du fichier chiffré
        with open(fichier_enc_path, "rb") as f:
            nonce = f.read(12)
            ciphertext = f.read()

        # Déchiffrement
        aesgcm = AESGCM(cle_aes)
        data = aesgcm.decrypt(nonce, ciphertext, None)

        # Sauvegarde
        with open(fichier_out_path, "wb") as f:
            f.write(data)

        return True

    except Exception as e:
        print(f"❌ Erreur déchiffrement AES : {e}")
        return False


# ============================================================================
# 3. CHIFFREMENT DE LA CLÉ AES AVEC X25519
# ============================================================================

def chiffrer_cle_aes(cle_aes, pubkey):
    """
    Chiffre une clé AES avec X25519 (ECDH + HKDF + AES-GCM).

    Args:
        cle_aes: Clé AES à chiffrer (32 bytes)
        pubkey: Clé publique X25519 du destinataire

    Returns:
        bytes: Clé AES chiffrée (format : ephemeral_pubkey + nonce + ciphertext)
    """
    try:
        # Génération clé éphémère
        ephemeral_privkey = X25519PrivateKey.generate()
        ephemeral_pubkey = ephemeral_privkey.public_key()

        # ECDH : calcul secret partagé
        shared_secret = ephemeral_privkey.exchange(pubkey)

        # Dérivation de clé (HKDF-SHA256)
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'nas-aes-key-encryption'
        )
        derived_key = kdf.derive(shared_secret)

        # Chiffrement de la clé AES
        aesgcm = AESGCM(derived_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, cle_aes, None)

        # Format : ephemeral_pubkey (32) + nonce (12) + ciphertext (32 + 16 tag)
        ephemeral_pubkey_bytes = ephemeral_pubkey.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        return ephemeral_pubkey_bytes + nonce + ciphertext

    except Exception as e:
        print(f"❌ Erreur chiffrement clé AES : {e}")
        return None


def dechiffrer_cle_aes(cle_aes_enc, privkey):
    """
    Déchiffre une clé AES avec X25519 (ECDH + HKDF + AES-GCM).

    Args:
        cle_aes_enc: Clé AES chiffrée (ephemeral_pubkey + nonce + ciphertext)
        privkey: Clé privée X25519

    Returns:
        bytes: Clé AES (32 bytes) ou None en cas d'erreur
    """
    try:
        # Parsing : 32 bytes pubkey + 12 bytes nonce + reste ciphertext
        ephemeral_pubkey_bytes = cle_aes_enc[:32]
        nonce = cle_aes_enc[32:44]
        ciphertext = cle_aes_enc[44:]

        # Reconstruction de la clé publique éphémère
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

        # Déchiffrement
        aesgcm = AESGCM(derived_key)
        cle_aes = aesgcm.decrypt(nonce, ciphertext, None)

        return cle_aes

    except Exception as e:
        print(f"❌ Erreur déchiffrement clé AES : {e}")
        return None


# ============================================================================
# 4. API HAUT NIVEAU
# ============================================================================

def chiffrer_fichier_complet(fichier_path, user_pubkey_path, output_dir="."):
    """
    Chiffre un fichier complet (fichier + clé AES).

    Args:
        fichier_path: Chemin du fichier à chiffrer
        user_pubkey_path: Chemin de la clé publique de l'utilisateur
        output_dir: Répertoire de sortie

    Returns:
        tuple: (fichier_enc_path, cle_aes_enc_path) ou (None, None)
    """
    try:
        os.makedirs(output_dir, exist_ok=True)

        # Chiffrement du fichier avec AES
        fichier_enc_path = os.path.join(output_dir, os.path.basename(fichier_path) + ".enc")
        cle_aes, _ = chiffrer_fichier_aes(fichier_path, fichier_enc_path)

        if not cle_aes:
            return None, None

        # Chiffrement de la clé AES avec X25519
        pubkey = charger_cle_publique(user_pubkey_path)
        cle_aes_enc = chiffrer_cle_aes(cle_aes, pubkey)

        if not cle_aes_enc:
            return None, None

        # Sauvegarde de la clé AES chiffrée
        cle_aes_enc_path = os.path.join(output_dir, os.path.basename(fichier_path) + ".key")
        with open(cle_aes_enc_path, "wb") as f:
            f.write(cle_aes_enc)

        return fichier_enc_path, cle_aes_enc_path

    except Exception as e:
        print(f"❌ Erreur chiffrement complet : {e}")
        return None, None


def dechiffrer_fichier_complet(fichier_enc_path, cle_aes_enc_path, user_privkey_path, output_dir="."):
    """
    Déchiffre un fichier complet (clé AES puis fichier).

    Args:
        fichier_enc_path: Chemin du fichier chiffré
        cle_aes_enc_path: Chemin de la clé AES chiffrée
        user_privkey_path: Chemin de la clé privée de l'utilisateur
        output_dir: Répertoire de sortie

    Returns:
        str: Chemin du fichier déchiffré ou None
    """
    try:
        os.makedirs(output_dir, exist_ok=True)

        # Chargement de la clé privée
        privkey = charger_cle_privee(user_privkey_path)

        # Déchiffrement de la clé AES
        with open(cle_aes_enc_path, "rb") as f:
            cle_aes_enc = f.read()

        cle_aes = dechiffrer_cle_aes(cle_aes_enc, privkey)

        if not cle_aes:
            return None

        # Déchiffrement du fichier
        fichier_out_path = os.path.join(output_dir, os.path.basename(fichier_enc_path).replace(".enc", ""))

        if not dechiffrer_fichier_aes(fichier_enc_path, fichier_out_path, cle_aes):
            return None

        return fichier_out_path

    except Exception as e:
        print(f"❌ Erreur déchiffrement complet : {e}")
        return None


# ============================================================================
# 5. SCRIPT DE TEST
# ============================================================================

if __name__ == "__main__":
    print("🔐 Test du système de chiffrement côté client\n")

    # Test 1 : Génération de clés
    print("1️⃣  Génération de clés X25519...")
    privkey_path, pubkey_path = generer_cles_utilisateur(".test_keys")
    print(f"   ✅ Clé privée : {privkey_path}")
    print(f"   ✅ Clé publique : {pubkey_path}\n")

    # Test 2 : Création d'un fichier de test
    print("2️⃣  Création d'un fichier de test...")
    test_file = ".test_keys/test_data.txt"
    with open(test_file, "w") as f:
        f.write("Données confidentielles du NAS sécurisé !")
    print(f"   ✅ Fichier créé : {test_file}\n")

    # Test 3 : Chiffrement complet
    print("3️⃣  Chiffrement complet...")
    enc_file, key_file = chiffrer_fichier_complet(test_file, pubkey_path, ".test_keys")
    print(f"   ✅ Fichier chiffré : {enc_file}")
    print(f"   ✅ Clé AES chiffrée : {key_file}\n")

    # Test 4 : Déchiffrement complet
    print("4️⃣  Déchiffrement complet...")
    dec_file = dechiffrer_fichier_complet(enc_file, key_file, privkey_path, ".test_keys")
    print(f"   ✅ Fichier déchiffré : {dec_file}\n")

    # Test 5 : Vérification
    print("5️⃣  Vérification...")
    with open(dec_file, "r") as f:
        content = f.read()
    print(f"   ✅ Contenu : {content}\n")

    # Nettoyage
    print("6️⃣  Nettoyage...")
    import shutil
    shutil.rmtree(".test_keys")
    print("   ✅ Fichiers de test supprimés\n")

    print("✅ Tous les tests sont passés avec succès !")
