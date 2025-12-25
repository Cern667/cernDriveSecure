#!/usr/bin/env python3
"""
Security manager for NAS
Manages security levels and device registration
"""

import os
import json
import hashlib
from datetime import datetime
from typing import Optional, Dict, List

# Configuration paths
SECURITY_CONFIG_DIR = '/app/security_config'
USERS_SECURITY_FILE = os.path.join(SECURITY_CONFIG_DIR, 'users_security.json')
DEVICES_REGISTRY_FILE = os.path.join(SECURITY_CONFIG_DIR, 'devices_registry.json')

# Security levels
SECURITY_LEVEL_STANDARD = "standard"
SECURITY_LEVEL_MAXIMUM = "maximum"


class SecurityManager:
    """Centralized user security manager"""

    def __init__(self):
        """Initializes the security manager"""
        os.makedirs(SECURITY_CONFIG_DIR, exist_ok=True)
        self._load_configs()

    def _load_configs(self):
        """Loads security configurations"""
        # User security level configuration
        if os.path.exists(USERS_SECURITY_FILE):
            with open(USERS_SECURITY_FILE, 'r') as f:
                self.users_security = json.load(f)
        else:
            self.users_security = {}
            self._save_users_security()

        # Authorized devices registry
        if os.path.exists(DEVICES_REGISTRY_FILE):
            with open(DEVICES_REGISTRY_FILE, 'r') as f:
                self.devices_registry = json.load(f)
        else:
            self.devices_registry = {}
            self._save_devices_registry()

    def _save_users_security(self):
        """Saves user configuration"""
        with open(USERS_SECURITY_FILE, 'w') as f:
            json.dump(self.users_security, f, indent=2)

    def _save_devices_registry(self):
        """Saves device registry"""
        with open(DEVICES_REGISTRY_FILE, 'w') as f:
            json.dump(self.devices_registry, f, indent=2)

    # =========================================================================
    # GESTION DES NIVEAUX DE SÉCURITÉ
    # =========================================================================

    def get_user_security_level(self, username: str) -> str:
        """
        Retrieves user's security level

        Args:
            username: Username

        Returns:
            Security level (standard or maximum)
        """
        return self.users_security.get(username, {}).get('level', SECURITY_LEVEL_STANDARD)

    def set_user_security_level(self, username: str, level: str) -> bool:
        """
        Sets user's security level

        Args:
            username: Username
            level: Security level (standard or maximum)

        Returns:
            True if success, False otherwise
        """
        if level not in [SECURITY_LEVEL_STANDARD, SECURITY_LEVEL_MAXIMUM]:
            return False

        if username not in self.users_security:
            self.users_security[username] = {}

        old_level = self.users_security[username].get('level')
        self.users_security[username]['level'] = level
        self.users_security[username]['updated_at'] = datetime.now().isoformat()

        # If switching to maximum mode, mark migration as needed
        if old_level == SECURITY_LEVEL_STANDARD and level == SECURITY_LEVEL_MAXIMUM:
            self.users_security[username]['migration_needed'] = True

        self._save_users_security()
        return True

    def is_maximum_security(self, username: str) -> bool:
        """Checks if user is in maximum security mode"""
        return self.get_user_security_level(username) == SECURITY_LEVEL_MAXIMUM

    # =========================================================================
    # GESTION DES APPAREILS
    # =========================================================================

    def generate_device_fingerprint(self, user_agent: str, ip_address: str,
                                   accept_language: str = "",
                                   screen_info: str = "") -> str:
        """
        Generates unique fingerprint for a device

        Args:
            user_agent: Browser User-Agent
            ip_address: Adresse IP
            accept_language: Browser language
            screen_info: Screen information (resolution, etc.)

        Returns:
            Unique device fingerprint (SHA256 hash)
        """
        # Combine multiple pieces of information to create unique fingerprint
        fingerprint_data = f"{user_agent}|{accept_language}|{screen_info}"
        fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()
        return fingerprint

    def register_device(self, username: str, device_fingerprint: str,
                       device_info: Dict) -> bool:
        """
        Registers a new device for a user

        Args:
            username: Username
            device_fingerprint: Device fingerprint
            device_info: Device information (user_agent, ip, etc.)

        Returns:
            True if success, False otherwise
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
        Checks if a device is registered for a user

        Args:
            username: Username
            device_fingerprint: Device fingerprint

        Returns:
            True if device is registered, False otherwise
        """
        if username not in self.devices_registry:
            return False

        return device_fingerprint in self.devices_registry[username]

    def update_device_last_seen(self, username: str, device_fingerprint: str):
        """Updates device last connection"""
        if username in self.devices_registry and device_fingerprint in self.devices_registry[username]:
            self.devices_registry[username][device_fingerprint]['last_seen'] = datetime.now().isoformat()
            self._save_devices_registry()

    def get_user_devices(self, username: str) -> List[Dict]:
        """
        Retrieves list of registered devices for a user

        Args:
            username: Username

        Returns:
            List of devices with their information
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

        # Sort by registration date (newest first)
        devices.sort(key=lambda x: x.get('registered_at', ''), reverse=True)
        return devices

    def revoke_device(self, username: str, device_fingerprint: str) -> bool:
        """
        Revokes device access

        Args:
            username: Username
            device_fingerprint: Device fingerprint

        Returns:
            True if success, False otherwise
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
        Checks if a device can access files

        Args:
            username: Username
            device_fingerprint: Device fingerprint

        Returns:
            Tuple (authorization, message)
        """
        security_level = self.get_user_security_level(username)

        # Standard mode: access authorized
        if security_level == SECURITY_LEVEL_STANDARD:
            return True, "Access authorized (standard mode)"

        # Mode sécurité maximale : vérifier que la clé privée chiffrée existe sur le serveur
        # En mode "maximum avec serveur", la clé privée chiffrée est stockée dans authorized_devices.json
        # L'utilisateur déchiffre côté client avec son mot de passe

        # Check if user has encrypted private key stored on server
        import sys
        import os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from lib.auth.device_manager import has_registered_key

        if not has_registered_key(username):
            return False, "Private key not configured. Please configure your encryption keys."

        # Si l'utilisateur a une clé chiffrée sur le serveur, l'accès est autorisé
        # (il devra entrer son mot de passe côté client pour déchiffrer)
        return True, "Access authorized (maximum security mode with server)"

    def mark_device_has_key(self, username: str, device_fingerprint: str):
        """Marks that a device has the private key"""
        if username in self.devices_registry and device_fingerprint in self.devices_registry[username]:
            self.devices_registry[username][device_fingerprint]['has_private_key'] = True
            self._save_devices_registry()

    # =========================================================================
    # UTILITAIRES
    # =========================================================================

    def get_security_stats(self, username: str) -> Dict:
        """Retrieves user security statistics"""
        return {
            'security_level': self.get_user_security_level(username),
            'registered_devices_count': len(self.devices_registry.get(username, {})),
            'is_maximum_security': self.is_maximum_security(username)
        }


# Instance globale
_security_manager = None

def get_security_manager() -> SecurityManager:
    """Retrieves global security manager instance"""
    global _security_manager
    if _security_manager is None:
        _security_manager = SecurityManager()
    return _security_manager
