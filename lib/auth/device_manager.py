#!/usr/bin/env python3
"""
Gestionnaire d'appareils autorisés pour le mode Zero-Knowledge
Permet de gérer les appareils de confiance pour chaque utilisateur
"""

import os
import json
import hashlib
from datetime import datetime
from typing import List, Dict, Optional

# Fichier de stockage des appareils autorisés
DEVICES_FILE = '/app/data/authorized_devices.json'

def _ensure_data_dir():
    """Crée le répertoire data s'il n'existe pas"""
    os.makedirs(os.path.dirname(DEVICES_FILE), exist_ok=True)

def _load_devices() -> Dict:
    """Charge la base de données des appareils"""
    _ensure_data_dir()
    if not os.path.exists(DEVICES_FILE):
        return {}
    
    try:
        with open(DEVICES_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"⚠️ Erreur chargement devices: {e}")
        return {}

def _save_devices(devices: Dict):
    """Sauvegarde la base de données des appareils"""
    _ensure_data_dir()
    try:
        with open(DEVICES_FILE, 'w') as f:
            json.dump(devices, f, indent=2)
    except Exception as e:
        print(f"❌ Erreur sauvegarde devices: {e}")

def _generate_device_id(username: str, device_fingerprint: str) -> str:
    """Génère un ID unique pour un appareil"""
    data = f"{username}:{device_fingerprint}"
    return hashlib.sha256(data.encode()).hexdigest()[:16]

def register_device(
    username: str,
    device_fingerprint: str,
    device_info: Dict,
    encrypted_private_key: str,
    salt: str,
    iv: str,
    device_public_key_ed25519: str = None,
    authorized_by_device_id: str = None
) -> Dict:
    """
    Enregistre un nouvel appareil pour un utilisateur
    
    Args:
        username: Nom d'utilisateur
        device_fingerprint: Empreinte unique de l'appareil
        device_info: Informations sur l'appareil (nom, navigateur, OS, etc.)
        encrypted_private_key: Clé privée chiffrée avec le mot de passe (base64)
        salt: Salt utilisé pour PBKDF2 (base64)
        iv: IV utilisé pour chiffrement (base64)
    
    Returns:
        Dict avec success, device_id, message
    """
    devices = _load_devices()
    
    # Initialiser l'utilisateur s'il n'existe pas
    if username not in devices:
        devices[username] = {
            "devices": [],
            "encrypted_private_key": encrypted_private_key,
            "salt": salt,
            "iv": iv,
            "created_at": datetime.utcnow().isoformat()
        }
    
    # Vérifier si l'appareil existe déjà
    device_id = _generate_device_id(username, device_fingerprint)
    
    for device in devices[username]["devices"]:
        if device["device_id"] == device_id:
            # Appareil déjà enregistré, mise à jour last_used
            device["last_used"] = datetime.utcnow().isoformat()
            _save_devices(devices)
            return {
                "success": True,
                "device_id": device_id,
                "message": "Appareil déjà enregistré",
                "is_new": False
            }
    
    # Nouvel appareil
    new_device = {
        "device_id": device_id,
        "fingerprint": device_fingerprint,
        "device_public_key_ed25519": device_public_key_ed25519,  # Clé signature appareil
        "device_name": device_info.get("device_name", "Unknown Device"),
        "user_agent": device_info.get("user_agent", ""),
        "screen_info": device_info.get("screen_info", ""),
        "language": device_info.get("language", ""),
        "status": "authorized" if authorized_by_device_id is None else "authorized",
        "authorized_at": datetime.utcnow().isoformat(),
        "authorized_by": authorized_by_device_id,  # None = premier appareil, sinon device_id qui a autorisé
        "created_at": datetime.utcnow().isoformat(),
        "last_used": datetime.utcnow().isoformat(),
        "revoked": False
    }
    
    devices[username]["devices"].append(new_device)
    _save_devices(devices)
    
    print(f"✅ Nouvel appareil enregistré pour {username}: {device_id}")
    return {
        "success": True,
        "device_id": device_id,
        "message": "Appareil enregistré avec succès",
        "is_new": True
    }

def is_device_authorized(username: str, device_fingerprint: str) -> bool:
    """
    Vérifie si un appareil est autorisé pour un utilisateur
    
    Args:
        username: Nom d'utilisateur
        device_fingerprint: Empreinte de l'appareil
    
    Returns:
        True si autorisé, False sinon
    """
    devices = _load_devices()
    
    if username not in devices:
        return False
    
    device_id = _generate_device_id(username, device_fingerprint)
    
    for device in devices[username]["devices"]:
        if device["device_id"] == device_id and not device.get("revoked", False):
            # Mettre à jour last_used
            device["last_used"] = datetime.utcnow().isoformat()
            _save_devices(devices)
            return True
    
    return False

def get_encrypted_private_key(username: str) -> Optional[Dict]:
    """
    Récupère la clé privée chiffrée d'un utilisateur
    
    Args:
        username: Nom d'utilisateur
    
    Returns:
        Dict avec encrypted_key, salt, iv ou None
    """
    devices = _load_devices()
    
    if username not in devices:
        return None
    
    user_data = devices[username]
    return {
        "encrypted_private_key": user_data.get("encrypted_private_key"),
        "salt": user_data.get("salt"),
        "iv": user_data.get("iv")
    }

def list_user_devices(username: str) -> List[Dict]:
    """
    Liste tous les appareils d'un utilisateur
    
    Args:
        username: Nom d'utilisateur
    
    Returns:
        Liste des appareils avec leurs informations
    """
    devices = _load_devices()
    
    if username not in devices:
        return []
    
    return devices[username]["devices"]

def revoke_device(username: str, device_id: str) -> Dict:
    """
    Révoque un appareil
    
    Args:
        username: Nom d'utilisateur
        device_id: ID de l'appareil à révoquer
    
    Returns:
        Dict avec success et message
    """
    devices = _load_devices()
    
    if username not in devices:
        return {"success": False, "message": "Utilisateur introuvable"}
    
    for device in devices[username]["devices"]:
        if device["device_id"] == device_id:
            device["revoked"] = True
            device["revoked_at"] = datetime.utcnow().isoformat()
            _save_devices(devices)
            
            print(f"🚫 Appareil révoqué pour {username}: {device_id}")
            return {"success": True, "message": "Appareil révoqué"}
    
    return {"success": False, "message": "Appareil introuvable"}

def delete_user_devices(username: str):
    """
    Supprime tous les appareils d'un utilisateur (lors d'une purge)
    
    Args:
        username: Nom d'utilisateur
    """
    devices = _load_devices()
    
    if username in devices:
        del devices[username]
        _save_devices(devices)
        print(f"🗑️ Appareils supprimés pour {username}")

def has_registered_key(username: str) -> bool:
    """
    Vérifie si un utilisateur a déjà enregistré une clé privée chiffrée
    
    Args:
        username: Nom d'utilisateur
    
    Returns:
        True si une clé est enregistrée, False sinon
    """
    devices = _load_devices()
    return username in devices and "encrypted_private_key" in devices[username]

def purge_all_devices():
    """Supprime tous les appareils (lors d'un changement de mode de sécurité)"""
    _ensure_data_dir()
    if os.path.exists(DEVICES_FILE):
        os.remove(DEVICES_FILE)
        print("🗑️ Tous les appareils supprimés")

# ============================================================================
# TESTS
# ============================================================================

if __name__ == "__main__":
    print("🧪 Tests du gestionnaire d'appareils\n")
    
    # Test 1 : Enregistrement d'un appareil
    print("1️⃣ Enregistrement d'un appareil...")
    result = register_device(
        username="testuser",
        device_fingerprint="abc123def456",
        device_info={
            "device_name": "Chrome on Windows PC",
            "user_agent": "Mozilla/5.0...",
            "screen_info": "1920x1080",
            "language": "fr-FR"
        },
        encrypted_private_key="base64_encrypted_key",
        salt="base64_salt",
        iv="base64_iv"
    )
    print(f"   {result}\n")
    
    # Test 2 : Vérification autorisation
    print("2️⃣ Vérification autorisation...")
    authorized = is_device_authorized("testuser", "abc123def456")
    print(f"   ✅ Autorisé: {authorized}\n")
    
    # Test 3 : Liste des appareils
    print("3️⃣ Liste des appareils...")
    devices_list = list_user_devices("testuser")
    print(f"   📱 {len(devices_list)} appareil(s)\n")
    
    # Test 4 : Récupération clé chiffrée
    print("4️⃣ Récupération clé chiffrée...")
    key_data = get_encrypted_private_key("testuser")
    print(f"   🔑 Clé: {key_data['encrypted_private_key'][:20]}...\n")
    
    # Test 5 : Révocation
    print("5️⃣ Révocation d'un appareil...")
    device_id = devices_list[0]["device_id"]
    revoke_result = revoke_device("testuser", device_id)
    print(f"   {revoke_result}\n")
    
    # Nettoyage
    print("6️⃣ Nettoyage...")
    purge_all_devices()
    print("   ✅ Tests terminés\n")
