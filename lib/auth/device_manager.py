#!/usr/bin/env python3
"""
Device manager for Zero-Knowledge mode
Manages trusted devices for each user
"""

import os
import json
import hashlib
from datetime import datetime
from typing import List, Dict, Optional

DEVICES_FILE = '/app/data/authorized_devices.json'

def _ensure_data_dir():
    """Creates data directory if it doesn't exist"""
    os.makedirs(os.path.dirname(DEVICES_FILE), exist_ok=True)

def _load_devices() -> Dict:
    """Loads the device database"""
    _ensure_data_dir()
    if not os.path.exists(DEVICES_FILE):
        return {}

    try:
        with open(DEVICES_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Warning: Error loading devices: {e}")
        return {}

def _save_devices(devices: Dict):
    """Saves the device database"""
    _ensure_data_dir()
    try:
        with open(DEVICES_FILE, 'w') as f:
            json.dump(devices, f, indent=2)
    except Exception as e:
        print(f"Error saving devices: {e}")

def _generate_device_id(username: str, device_fingerprint: str) -> str:
    """Generates a unique ID for a device"""
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
    Registers a new device for a user

    Args:
        username: Username
        device_fingerprint: Unique device fingerprint
        device_info: Device information (name, browser, OS, etc.)
        encrypted_private_key: Private key encrypted with password (base64)
        salt: Salt used for PBKDF2 (base64)
        iv: IV used for encryption (base64)
        device_public_key_ed25519: Device signing key (Ed25519)
        authorized_by_device_id: Device ID that authorized this device (None for first device)

    Returns:
        Dict with success, device_id, message
    """
    devices = _load_devices()

    # Initialize user if not exists
    if username not in devices:
        devices[username] = {
            "devices": [],
            "encrypted_private_key": encrypted_private_key,
            "salt": salt,
            "iv": iv,
            "created_at": datetime.utcnow().isoformat()
        }

    # Check if device already exists
    device_id = _generate_device_id(username, device_fingerprint)

    for device in devices[username]["devices"]:
        if device["device_id"] == device_id:
            # Device already registered, update last_used
            device["last_used"] = datetime.utcnow().isoformat()
            _save_devices(devices)
            return {
                "success": True,
                "device_id": device_id,
                "message": "Device already registered",
                "is_new": False
            }

    # New device
    new_device = {
        "device_id": device_id,
        "fingerprint": device_fingerprint,
        "device_public_key_ed25519": device_public_key_ed25519,
        "device_name": device_info.get("device_name", "Unknown Device"),
        "user_agent": device_info.get("user_agent", ""),
        "screen_info": device_info.get("screen_info", ""),
        "language": device_info.get("language", ""),
        "status": "authorized" if authorized_by_device_id is None else "authorized",
        "authorized_at": datetime.utcnow().isoformat(),
        "authorized_by": authorized_by_device_id,
        "created_at": datetime.utcnow().isoformat(),
        "last_used": datetime.utcnow().isoformat(),
        "revoked": False
    }

    devices[username]["devices"].append(new_device)
    _save_devices(devices)

    print(f"New device registered for {username}: {device_id}")
    return {
        "success": True,
        "device_id": device_id,
        "message": "Device registered successfully",
        "is_new": True
    }

def is_device_authorized(username: str, device_fingerprint: str) -> bool:
    """
    Checks if a device is authorized for a user

    Args:
        username: Username
        device_fingerprint: Device fingerprint

    Returns:
        True if authorized, False otherwise
    """
    devices = _load_devices()

    if username not in devices:
        return False

    device_id = _generate_device_id(username, device_fingerprint)

    for device in devices[username]["devices"]:
        if device["device_id"] == device_id and not device.get("revoked", False):
            # Update last_used
            device["last_used"] = datetime.utcnow().isoformat()
            _save_devices(devices)
            return True

    return False

def get_encrypted_private_key(username: str) -> Optional[Dict]:
    """
    Retrieves user's encrypted private key

    Args:
        username: Username

    Returns:
        Dict with encrypted_key, salt, iv, created_at or None
    """
    devices = _load_devices()

    if username not in devices:
        return None

    user_data = devices[username]
    return {
        "encrypted_private_key": user_data.get("encrypted_private_key"),
        "salt": user_data.get("salt"),
        "iv": user_data.get("iv"),
        "created_at": user_data.get("created_at")
    }

def list_user_devices(username: str) -> List[Dict]:
    """
    Lists all devices for a user

    Args:
        username: Username

    Returns:
        List of devices with their information
    """
    devices = _load_devices()
    
    if username not in devices:
        return []
    
    return devices[username]["devices"]

def revoke_device(username: str, device_id: str) -> Dict:
    """
    Revokes a device

    Args:
        username: Username
        device_id: Device ID to revoke

    Returns:
        Dict with success and message
    """
    devices = _load_devices()

    if username not in devices:
        return {"success": False, "message": "User not found"}

    for device in devices[username]["devices"]:
        if device["device_id"] == device_id:
            device["revoked"] = True
            device["revoked_at"] = datetime.utcnow().isoformat()
            _save_devices(devices)

            print(f"Device revoked for {username}: {device_id}")
            return {"success": True, "message": "Device revoked"}

    return {"success": False, "message": "Device not found"}

def delete_user_devices(username: str):
    """
    Deletes all devices for a user (during purge)

    Args:
        username: Username
    """
    devices = _load_devices()

    if username in devices:
        del devices[username]
        _save_devices(devices)
        print(f"Devices deleted for {username}")

def get_user_key_type(username: str) -> Optional[str]:
    """
    Detects the type of user's public key

    Args:
        username: Username

    Returns:
        'X25519' if X25519 key (maximum mode)
        'EC' if EC key (standard mode)
        None if no key
    """
    public_key_path = f'/app/user_keys/{username}/public_key.pem'

    if not os.path.exists(public_key_path):
        return None

    try:
        with open(public_key_path, 'rb') as f:
            key_data = f.read()

        # X25519 keys are very short (~44 bytes in base64)
        # EC P-256 keys are longer (~91 bytes in base64)

        if b'MCowBQYDK2VuAyEA' in key_data or len(key_data) < 100:
            # Typical X25519 format: MCowBQYDK2VuAyEA...
            return 'X25519'
        elif b'MFkwEwYHKoZIzj0' in key_data:
            # Typical EC format: MFkwEwYHKoZIzj0...
            return 'EC'
        else:
            # Try to determine by size
            import base64
            lines = key_data.decode().strip().split('\n')
            if len(lines) >= 3:
                b64_data = ''.join(lines[1:-1])
                if len(b64_data) < 60:
                    return 'X25519'
                else:
                    return 'EC'
    except Exception as e:
        print(f"Warning: Error detecting key type for {username}: {e}")
        return None

    return None

def has_registered_key(username: str) -> bool:
    """
    Checks if a user has already registered an encrypted private key

    Args:
        username: Username

    Returns:
        True if key is registered, False otherwise
    """
    devices = _load_devices()
    return username in devices and "encrypted_private_key" in devices[username]

def has_compatible_keys(username: str, expected_mode: str) -> bool:
    """
    Checks if user has keys compatible with expected security mode

    Args:
        username: Username
        expected_mode: 'maximum' or 'normal'

    Returns:
        True if keys are compatible, False otherwise
    """
    key_type = get_user_key_type(username)

    if key_type is None:
        return False

    # Both modes accept EC (P-256) and X25519
    # Because Web Crypto API generates P-256 as fallback if X25519 not supported
    return key_type in ['EC', 'X25519']

def purge_all_devices():
    """Deletes all devices (during security mode change)"""
    _ensure_data_dir()
    if os.path.exists(DEVICES_FILE):
        os.remove(DEVICES_FILE)
        print("All devices deleted")

# Tests
if __name__ == "__main__":
    print("Device manager tests\n")

    # Test 1: Register device
    print("1. Registering device...")
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

    # Test 2: Check authorization
    print("2. Checking authorization...")
    authorized = is_device_authorized("testuser", "abc123def456")
    print(f"   Authorized: {authorized}\n")

    # Test 3: List devices
    print("3. Listing devices...")
    devices_list = list_user_devices("testuser")
    print(f"   {len(devices_list)} device(s)\n")

    # Test 4: Retrieve encrypted key
    print("4. Retrieving encrypted key...")
    key_data = get_encrypted_private_key("testuser")
    print(f"   Key: {key_data['encrypted_private_key'][:20]}...\n")

    # Test 5: Revoke device
    print("5. Revoking device...")
    device_id = devices_list[0]["device_id"]
    revoke_result = revoke_device("testuser", device_id)
    print(f"   {revoke_result}\n")

    # Cleanup
    print("6. Cleanup...")
    purge_all_devices()
    print("   Tests completed\n")
