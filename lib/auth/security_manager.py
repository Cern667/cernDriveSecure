#!/usr/bin/env python3
"""
Gestionnaire de sécurité pour le NAS
Gère les niveaux de sécurité et l'enregistrement des appareils
"""

import os
import json
import hashlib
from datetime import datetime
from typing import Optional, Dict, List

# Chemins de configuration
SECURITY_CONFIG_DIR = '/app/security_config'
USERS_SECURITY_FILE = os.path.join(SECURITY_CONFIG_DIR, 'users_security.json')
DEVICES_REGISTRY_FILE = os.path.join(SECURITY_CONFIG_DIR, 'devices_registry.json')

# Niveaux de sécurité
SECURITY_LEVEL_STANDARD = "standard"
SECURITY_LEVEL_MAXIMUM = "maximum"


class SecurityManager:
    """Gestionnaire centralisé de la sécurité utilisateur"""

    def __init__(self):
        """Initialise le gestionnaire de sécurité"""
        os.makedirs(SECURITY_CONFIG_DIR, exist_ok=True)
        self._load_configs()

    def _load_configs(self):
        """Charge les configurations de sécurité"""
        # Configuration des niveaux de sécurité par utilisateur
        if os.path.exists(USERS_SECURITY_FILE):
            with open(USERS_SECURITY_FILE, 'r') as f:
                self.users_security = json.load(f)
        else:
            self.users_security = {}
            self._save_users_security()

        # Registre des appareils autorisés
        if os.path.exists(DEVICES_REGISTRY_FILE):
            with open(DEVICES_REGISTRY_FILE, 'r') as f:
                self.devices_registry = json.load(f)
        else:
            self.devices_registry = {}
            self._save_devices_registry()

    def _save_users_security(self):
        """Sauvegarde la configuration des utilisateurs"""
        with open(USERS_SECURITY_FILE, 'w') as f:
            json.dump(self.users_security, f, indent=2)

    def _save_devices_registry(self):
        """Sauvegarde le registre des appareils"""
        with open(DEVICES_REGISTRY_FILE, 'w') as f:
            json.dump(self.devices_registry, f, indent=2)

    # =========================================================================
    # GESTION DES NIVEAUX DE SÉCURITÉ
    # =========================================================================

    def get_user_security_level(self, username: str) -> str:
        """
        Récupère le niveau de sécurité d'un utilisateur

        Args:
            username: Nom d'utilisateur

        Returns:
            Niveau de sécurité (standard ou maximum)
        """
        return self.users_security.get(username, {}).get('level', SECURITY_LEVEL_STANDARD)

    def set_user_security_level(self, username: str, level: str) -> bool:
        """
        Définit le niveau de sécurité d'un utilisateur

        Args:
            username: Nom d'utilisateur
            level: Niveau de sécurité (standard ou maximum)

        Returns:
            True si succès, False sinon
        """
        if level not in [SECURITY_LEVEL_STANDARD, SECURITY_LEVEL_MAXIMUM]:
            return False

        if username not in self.users_security:
            self.users_security[username] = {}

        old_level = self.users_security[username].get('level')
        self.users_security[username]['level'] = level
        self.users_security[username]['updated_at'] = datetime.now().isoformat()

        # Si passage en mode maximum, marquer que la migration est nécessaire
        if old_level == SECURITY_LEVEL_STANDARD and level == SECURITY_LEVEL_MAXIMUM:
            self.users_security[username]['migration_needed'] = True

        self._save_users_security()
        return True

    def is_maximum_security(self, username: str) -> bool:
        """Vérifie si l'utilisateur est en mode sécurité maximale"""
        return self.get_user_security_level(username) == SECURITY_LEVEL_MAXIMUM

    # =========================================================================
    # GESTION DES APPAREILS
    # =========================================================================

    def generate_device_fingerprint(self, user_agent: str, ip_address: str,
                                   accept_language: str = "",
                                   screen_info: str = "") -> str:
        """
        Génère une empreinte unique pour un appareil

        Args:
            user_agent: User-Agent du navigateur
            ip_address: Adresse IP
            accept_language: Langue du navigateur
            screen_info: Informations d'écran (résolution, etc.)

        Returns:
            Empreinte unique de l'appareil (hash SHA256)
        """
        # Combiner plusieurs informations pour créer une empreinte unique
        fingerprint_data = f"{user_agent}|{accept_language}|{screen_info}"
        fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()
        return fingerprint

    def register_device(self, username: str, device_fingerprint: str,
                       device_info: Dict) -> bool:
        """
        Enregistre un nouvel appareil pour un utilisateur

        Args:
            username: Nom d'utilisateur
            device_fingerprint: Empreinte de l'appareil
            device_info: Informations sur l'appareil (user_agent, ip, etc.)

        Returns:
            True si succès, False sinon
        """
        if username not in self.devices_registry:
            self.devices_registry[username] = {}

        self.devices_registry[username][device_fingerprint] = {
            'registered_at': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat(),
            'user_agent': device_info.get('user_agent', ''),
            'ip_address': device_info.get('ip_address', ''),
            'device_name': device_info.get('device_name', 'Unknown Device'),
            'has_private_key': device_info.get('has_private_key', False)
        }

        self._save_devices_registry()
        return True

    def is_device_registered(self, username: str, device_fingerprint: str) -> bool:
        """
        Vérifie si un appareil est enregistré pour un utilisateur

        Args:
            username: Nom d'utilisateur
            device_fingerprint: Empreinte de l'appareil

        Returns:
            True si l'appareil est enregistré, False sinon
        """
        if username not in self.devices_registry:
            return False

        return device_fingerprint in self.devices_registry[username]

    def update_device_last_seen(self, username: str, device_fingerprint: str):
        """Met à jour la dernière connexion d'un appareil"""
        if username in self.devices_registry and device_fingerprint in self.devices_registry[username]:
            self.devices_registry[username][device_fingerprint]['last_seen'] = datetime.now().isoformat()
            self._save_devices_registry()

    def get_user_devices(self, username: str) -> List[Dict]:
        """
        Récupère la liste des appareils enregistrés pour un utilisateur

        Args:
            username: Nom d'utilisateur

        Returns:
            Liste des appareils avec leurs informations
        """
        if username not in self.devices_registry:
            return []

        devices = []
        for fingerprint, info in self.devices_registry[username].items():
            devices.append({
                'fingerprint': fingerprint,
                'fingerprint_short': fingerprint[:16] + '...',
                **info
            })

        # Trier par date d'enregistrement (plus récent en premier)
        devices.sort(key=lambda x: x.get('registered_at', ''), reverse=True)
        return devices

    def revoke_device(self, username: str, device_fingerprint: str) -> bool:
        """
        Révoque l'accès d'un appareil

        Args:
            username: Nom d'utilisateur
            device_fingerprint: Empreinte de l'appareil

        Returns:
            True si succès, False sinon
        """
        if username not in self.devices_registry:
            return False

        if device_fingerprint in self.devices_registry[username]:
            del self.devices_registry[username][device_fingerprint]
            self._save_devices_registry()
            return True

        return False

    # =========================================================================
    # CONTRÔLES D'ACCÈS
    # =========================================================================

    def can_access_files(self, username: str, device_fingerprint: str) -> tuple[bool, str]:
        """
        Vérifie si un appareil peut accéder aux fichiers

        Args:
            username: Nom d'utilisateur
            device_fingerprint: Empreinte de l'appareil

        Returns:
            Tuple (autorisation, message)
        """
        security_level = self.get_user_security_level(username)

        # Mode standard : accès autorisé
        if security_level == SECURITY_LEVEL_STANDARD:
            return True, "Accès autorisé (mode standard)"

        # Mode sécurité maximale : vérifier l'appareil
        if not self.is_device_registered(username, device_fingerprint):
            return False, "Appareil non autorisé. Votre clé privée doit être sur cet appareil."

        # Vérifier que l'appareil possède bien la clé privée
        device_info = self.devices_registry[username].get(device_fingerprint, {})
        if not device_info.get('has_private_key', False):
            return False, "Clé privée manquante sur cet appareil."

        # Mettre à jour la dernière connexion
        self.update_device_last_seen(username, device_fingerprint)

        return True, "Accès autorisé (mode sécurité maximale)"

    def mark_device_has_key(self, username: str, device_fingerprint: str):
        """Marque qu'un appareil possède la clé privée"""
        if username in self.devices_registry and device_fingerprint in self.devices_registry[username]:
            self.devices_registry[username][device_fingerprint]['has_private_key'] = True
            self._save_devices_registry()

    # =========================================================================
    # UTILITAIRES
    # =========================================================================

    def get_security_stats(self, username: str) -> Dict:
        """Récupère les statistiques de sécurité d'un utilisateur"""
        return {
            'security_level': self.get_user_security_level(username),
            'registered_devices_count': len(self.devices_registry.get(username, {})),
            'is_maximum_security': self.is_maximum_security(username)
        }


# Instance globale
_security_manager = None

def get_security_manager() -> SecurityManager:
    """Récupère l'instance globale du gestionnaire de sécurité"""
    global _security_manager
    if _security_manager is None:
        _security_manager = SecurityManager()
    return _security_manager
