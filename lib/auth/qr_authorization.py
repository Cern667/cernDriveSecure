#!/usr/bin/env python3
"""
Gestionnaire d'autorisation d'appareils via QR Code
Gère les sessions temporaires d'autorisation (60 secondes)
"""

import os
import json
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Tuple
import threading
import time

# Fichier de stockage des sessions d'autorisation (temporaire)
# Utilise /tmp pour tests locaux, /app/data en production Docker
import sys
if os.path.exists('/app/data'):
    SESSIONS_FILE = '/app/data/authorization_sessions.json'
else:
    SESSIONS_FILE = '/tmp/authorization_sessions.json'

# Lock pour accès concurrent
_sessions_lock = threading.Lock()

def _ensure_data_dir():
    """Crée le répertoire data s'il n'existe pas"""
    os.makedirs(os.path.dirname(SESSIONS_FILE), exist_ok=True)

def _load_sessions() -> Dict:
    """Charge les sessions d'autorisation"""
    _ensure_data_dir()
    if not os.path.exists(SESSIONS_FILE):
        return {}
    
    try:
        with open(SESSIONS_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"⚠️ Erreur chargement sessions: {e}")
        return {}

def _save_sessions(sessions: Dict):
    """Sauvegarde les sessions d'autorisation"""
    _ensure_data_dir()
    try:
        with open(SESSIONS_FILE, 'w') as f:
            json.dump(sessions, f, indent=2)
    except Exception as e:
        print(f"❌ Erreur sauvegarde sessions: {e}")

def _cleanup_expired_sessions():
    """Nettoie les sessions expirées"""
    with _sessions_lock:
        sessions = _load_sessions()
        now = datetime.utcnow()
        
        expired_sessions = []
        for session_id, session_data in sessions.items():
            expires_at = datetime.fromisoformat(session_data.get("expires_at", ""))
            if now > expires_at:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            del sessions[session_id]
        
        if expired_sessions:
            _save_sessions(sessions)
            print(f"🧹 {len(expired_sessions)} session(s) expirée(s) nettoyée(s)")


class AuthorizationSession:
    """Gestion des sessions d'autorisation par QR code"""
    
    @staticmethod
    def create_session(
        username: str,
        new_device_fingerprint: str,
        new_device_pubkey_ed25519: str,
        device_info: Dict,
        max_age_seconds: int = 60
    ) -> Dict:
        """
        Créeune session d'autorisation temporaire
        
        Args:
            username: Nom d'utilisateur
            new_device_fingerprint: Empreinte du nouvel appareil
            new_device_pubkey_ed25519: Clé publique Ed25519 du nouvel appareil
            device_info: Informations sur le nouvel appareil
            max_age_seconds: Durée de vie de la session (défaut: 60s)
        
        Returns:
            Dict avec session_id, expires_at, websocket_url
        """
        # Nettoyer les sessions expirées
        _cleanup_expired_sessions()
        
        # Générer un ID de session unique
        session_id = str(uuid.uuid4())
        
        # Calculer expiration
        created_at = datetime.utcnow()
        expires_at = created_at + timedelta(seconds=max_age_seconds)
        
        # Créer la session
        session_data = {
            "username": username,
            "new_device_fingerprint": new_device_fingerprint,
            "new_device_pubkey_ed25519": new_device_pubkey_ed25519,
            "device_info": device_info,
            "status": "pending",  # pending, authorized, expired, rejected
            "created_at": created_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "authorized_by_device_id": None,
            "timestamp": int(created_at.timestamp())
        }
        
        # Sauvegarder
        with _sessions_lock:
            sessions = _load_sessions()
            sessions[session_id] = session_data
            _save_sessions(sessions)
        
        print(f"📝 Session d'autorisation créée: {session_id} (expire dans {max_age_seconds}s)")
        
        return {
            "success": True,
            "session_id": session_id,
            "expires_at": expires_at.isoformat(),
            "timestamp": session_data["timestamp"],
            "websocket_url": f"/ws/auth/{session_id}"
        }
    
    @staticmethod
    def get_session(session_id: str) -> Optional[Dict]:
        """
        Récupère une session d'autorisation
        
        Args:
            session_id: ID de la session
        
        Returns:
            Données de la session ou None si inexistant/expiré
        """
        with _sessions_lock:
            sessions = _load_sessions()
            
            if session_id not in sessions:
                return None
            
            session_data = sessions[session_id]
            
            # Vérifier expiration
            expires_at = datetime.fromisoformat(session_data["expires_at"])
            if datetime.utcnow() > expires_at:
                # Session expirée
                session_data["status"] = "expired"
                _save_sessions(sessions)
                return session_data
            
            return session_data
    
    @staticmethod
    def authorize_session(
        session_id: str,
        signature_base64: str,
        signer_device_id: str,
        signer_pubkey_ed25519: str
    ) -> Tuple[bool, str, Optional[Dict]]:
        """
        Autorise une session après vérification de la signature
        
        Args:
            session_id: ID de la session
            signature_base64: Signature Ed25519 en base64
            signer_device_id: ID de l'appareil qui signe
            signer_pubkey_ed25519: Clé publique de l'appareil qui signe
        
        Returns:
            Tuple (succès, message, device_info)
        """
        # Récupérer la session
        session_data = AuthorizationSession.get_session(session_id)
        
        if not session_data:
            return False, "Session introuvable", None
        
        if session_data["status"] == "expired":
            return False, "Session expirée", None
        
        if session_data["status"] == "authorized":
            return False, "Session déjà autorisée", None
        
        # Vérifier la signature
        from device_keys import verify_authorization_signature, create_authorization_message
        
        timestamp = session_data["timestamp"]
        new_device_pubkey = session_data["new_device_pubkey_ed25519"]
        
        # Vérifier signature
        success, message = verify_authorization_signature(
            session_id,
            new_device_pubkey,
            timestamp,
            signature_base64,
            signer_pubkey_ed25519,
            max_age_seconds=120  # 2 minutes de tolérance
        )
        
        if not success:
            return False, f"Signature invalide: {message}", None
        
        # Autoriser la session
        with _sessions_lock:
            sessions = _load_sessions()
            if session_id in sessions:
                sessions[session_id]["status"] = "authorized"
                sessions[session_id]["authorized_by_device_id"] = signer_device_id
                sessions[session_id]["authorized_at"] = datetime.utcnow().isoformat()
                _save_sessions(sessions)
        
        print(f"✅ Session {session_id} autorisée par {signer_device_id}")
        
        # Retourner les infos du nouvel appareil
        device_info = {
            "fingerprint": session_data["new_device_fingerprint"],
            "device_public_key_ed25519": session_data["new_device_pubkey_ed25519"],
            "device_info": session_data["device_info"],
            "authorized_by": signer_device_id
        }
        
        return True, "Session autorisée", device_info
    
    @staticmethod
    def check_authorization_status(session_id: str) -> Dict:
        """
        Vérifie le statut d'autorisation d'une session
        
        Args:
            session_id: ID de la session
        
        Returns:
            Dict avec status (pending/authorized/expired/not_found)
        """
        session_data = AuthorizationSession.get_session(session_id)
        
        if not session_data:
            return {"status": "not_found"}
        
        return {
            "status": session_data["status"],
            "authorized_by": session_data.get("authorized_by_device_id")
        }
    
    @staticmethod
    def cleanup_all_sessions():
        """Supprime toutes les sessions (pour tests/nettoyage)"""
        _ensure_data_dir()
        if os.path.exists(SESSIONS_FILE):
            os.remove(SESSIONS_FILE)
            print("🗑️ Toutes les sessions supprimées")


# ============================================================================
# AUTO-CLEANUP THREAD (optionnel)
# ============================================================================

class SessionCleanupThread(threading.Thread):
    """Thread de nettoyage automatique des sessions expirées"""
    
    def __init__(self, interval_seconds=30):
        super().__init__(daemon=True)
        self.interval = interval_seconds
        self.running = True
    
    def run(self):
        while self.running:
            try:
                _cleanup_expired_sessions()
            except Exception as e:
                print(f"❌ Erreur cleanup thread: {e}")
            
            time.sleep(self.interval)
    
    def stop(self):
        self.running = False


# Global cleanup thread (démarre automatiquement)
_cleanup_thread = None

def start_cleanup_thread(interval_seconds=30):
    """Démarre le thread de nettoyage automatique"""
    global _cleanup_thread
    if _cleanup_thread is None or not _cleanup_thread.is_alive():
        _cleanup_thread = SessionCleanupThread(interval_seconds)
        _cleanup_thread.start()
        print(f"🧹 Thread de nettoyage démarré (intervalle: {interval_seconds}s)")


# ============================================================================
# TESTS
# ============================================================================

if __name__ == "__main__":
    print("🧪 Tests du gestionnaire d'autorisation QR\n")
    
    # Test 1 : Création de session
    print("1️⃣ Création d'une session d'autorisation...")
    session_result = AuthorizationSession.create_session(
        username="testuser",
        new_device_fingerprint="new_device_abc123",
        new_device_pubkey_ed25519="base64_ed25519_pubkey",
        device_info={
            "device_name": "Firefox on MacBook",
            "user_agent": "Mozilla/5.0...",
            "screen_info": "2560x1600"
        },
        max_age_seconds=60
    )
    print(f"   {session_result}\n")
    
    session_id = session_result["session_id"]
    
    # Test 2 : Récupération de session
    print("2️⃣ Récupération de la session...")
    session_data = AuthorizationSession.get_session(session_id)
    print(f"   ✅ Session trouvée: {session_data['status']}\n")
    
    # Test 3 : Vérification statut
    print("3️⃣ Vérification du statut...")
    status = AuthorizationSession.check_authorization_status(session_id)
    print(f"   📊 Statut: {status}\n")
    
    # Test 4 : Autorisation (simulation)
    print("4️⃣ Autorisation de la session...")
    
    # Générer une vraie paire de clés pour le test
    from device_keys import generate_device_keypair_ed25519, sign_message_ed25519, create_authorization_message
    import base64
    
    signer_privkey, signer_pubkey = generate_device_keypair_ed25519()
    signer_privkey_b64 = base64.b64encode(signer_privkey).decode('utf-8')
    signer_pubkey_b64 = base64.b64encode(signer_pubkey).decode('utf-8')
    
    # Créer le message d'autorisation
    auth_message = create_authorization_message(
        session_id,
        "base64_ed25519_pubkey",
        session_data["timestamp"]
    )
    
    # Signer
    signature = sign_message_ed25519(signer_privkey_b64, auth_message)
    
    # Autoriser
    success, message, device_info = AuthorizationSession.authorize_session(
        session_id,
        signature,
        "device_signer_123",
        signer_pubkey_b64
    )
    
    print(f"   ✅ Autorisation: {message}\n")
    
    # Test 5 : Vérifier changement de statut
    print("5️⃣ Vérification après autorisation...")
    status_after = AuthorizationSession.check_authorization_status(session_id)
    print(f"   📊 Nouveau statut: {status_after}\n")
    
    # Test 6 : Session expirée
    print("6️⃣ Test session expirée...")
    expired_session = AuthorizationSession.create_session(
        username="testuser2",
        new_device_fingerprint="device_xyz",
        new_device_pubkey_ed25519="pubkey_xyz",
        device_info={},
        max_age_seconds=0  # Expire immédiatement
    )
    
    time.sleep(1)
    expired_data = AuthorizationSession.get_session(expired_session["session_id"])
    print(f"   ⏰ Session expirée: {expired_data['status'] == 'expired'}\n")
    
    # Nettoyage
    print("7️⃣ Nettoyage...")
    AuthorizationSession.cleanup_all_sessions()
    print("   ✅ Tests terminés\n")
