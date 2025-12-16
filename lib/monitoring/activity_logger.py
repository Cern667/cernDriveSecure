#!/usr/bin/env python3
"""
Module de gestion des logs d'activité pour le NAS sécurisé
Enregistre toutes les actions des utilisateurs pour l'audit et la sécurité
"""

import os
import json
from datetime import datetime
from typing import Optional, Dict, List

# Configuration
LOGS_DIR = '/app/activity_logs'
LOGS_FILE = os.path.join(LOGS_DIR, 'activity.jsonl')  # JSON Lines format


class ActivityLogger:
    """Gestionnaire de logs d'activité"""

    def __init__(self):
        """Initialise le logger d'activité"""
        os.makedirs(LOGS_DIR, exist_ok=True)
        if not os.path.exists(LOGS_FILE):
            open(LOGS_FILE, 'a').close()  # Créer le fichier s'il n'existe pas

    def log_activity(self, username: str, action: str, ip_address: str,
                     status: str = 'SUCCESS', details: str = '',
                     device_fingerprint: str = '', user_agent: str = ''):
        """
        Enregistre une activité utilisateur

        Args:
            username: Nom d'utilisateur
            action: Type d'action (LOGIN, UPLOAD, DOWNLOAD, etc.)
            ip_address: Adresse IP source
            status: Statut de l'action (SUCCESS, FAILED, etc.)
            details: Détails supplémentaires
            device_fingerprint: Empreinte de l'appareil
            user_agent: User-Agent du navigateur
        """
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'username': username,
            'action': action,
            'ip_address': ip_address,
            'status': status,
            'details': details,
            'device_fingerprint': device_fingerprint[:16] + '...' if device_fingerprint else '',
            'user_agent': user_agent[:100] if user_agent else ''  # Limiter la longueur
        }

        # Écrire dans le fichier JSONL (une ligne JSON par log)
        with open(LOGS_FILE, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')

    def get_user_logs(self, username: str, limit: int = 100) -> List[Dict]:
        """
        Récupère les logs d'un utilisateur spécifique

        Args:
            username: Nom d'utilisateur
            limit: Nombre maximum de logs à retourner

        Returns:
            Liste des logs triés par date (plus récent en premier)
        """
        logs = []

        if not os.path.exists(LOGS_FILE):
            return logs

        # Lire le fichier et filtrer par utilisateur
        with open(LOGS_FILE, 'r') as f:
            for line in f:
                try:
                    log_entry = json.loads(line.strip())
                    if log_entry.get('username') == username:
                        logs.append(log_entry)
                except json.JSONDecodeError:
                    continue

        # Trier par timestamp (plus récent en premier)
        logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

        # Limiter le nombre de résultats
        return logs[:limit]

    def get_all_logs(self, limit: int = 500) -> List[Dict]:
        """
        Récupère tous les logs (admin uniquement)

        Args:
            limit: Nombre maximum de logs à retourner

        Returns:
            Liste des logs triés par date (plus récent en premier)
        """
        logs = []

        if not os.path.exists(LOGS_FILE):
            return logs

        # Lire tous les logs
        with open(LOGS_FILE, 'r') as f:
            for line in f:
                try:
                    log_entry = json.loads(line.strip())
                    logs.append(log_entry)
                except json.JSONDecodeError:
                    continue

        # Trier par timestamp (plus récent en premier)
        logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

        # Limiter le nombre de résultats
        return logs[:limit]

    def get_logs_stats(self, username: Optional[str] = None) -> Dict:
        """
        Calcule des statistiques sur les logs

        Args:
            username: Nom d'utilisateur (optionnel, pour filtrer)

        Returns:
            Dictionnaire de statistiques
        """
        logs = self.get_user_logs(username, limit=10000) if username else self.get_all_logs(limit=10000)

        total = len(logs)
        success_count = sum(1 for log in logs if log.get('status') == 'SUCCESS')
        failed_count = sum(1 for log in logs if log.get('status') == 'FAILED')

        # Compter les actions
        actions = {}
        for log in logs:
            action = log.get('action', 'UNKNOWN')
            actions[action] = actions.get(action, 0) + 1

        # Compter les IPs uniques
        unique_ips = len(set(log.get('ip_address', '') for log in logs))

        return {
            'total_events': total,
            'success_count': success_count,
            'failed_count': failed_count,
            'actions': actions,
            'unique_ips': unique_ips
        }

    def get_security_alerts(self, username: Optional[str] = None) -> List[Dict]:
        """
        Récupère les alertes de sécurité (tentatives échouées, etc.)

        Args:
            username: Nom d'utilisateur (optionnel)

        Returns:
            Liste des alertes de sécurité
        """
        logs = self.get_user_logs(username, limit=1000) if username else self.get_all_logs(limit=1000)

        # Filtrer les événements de sécurité
        alerts = [
            log for log in logs
            if log.get('status') == 'FAILED' or 'FAILED' in log.get('action', '')
        ]

        return alerts[:50]  # Limiter à 50 alertes

    def clear_logs(self, username: Optional[str] = None) -> bool:
        """
        Efface tous les logs (admin uniquement) ou les logs d'un utilisateur spécifique

        Args:
            username: Nom d'utilisateur (optionnel, pour effacer uniquement ses logs)

        Returns:
            True si succès, False sinon
        """
        try:
            if not os.path.exists(LOGS_FILE):
                return True  # Rien à effacer

            if username is None:
                # Effacer tous les logs (admin)
                open(LOGS_FILE, 'w').close()
                return True
            else:
                # Effacer uniquement les logs de cet utilisateur
                all_logs = []
                with open(LOGS_FILE, 'r') as f:
                    for line in f:
                        try:
                            log_entry = json.loads(line.strip())
                            # Garder les logs des autres utilisateurs
                            if log_entry.get('username') != username:
                                all_logs.append(line.strip())
                        except json.JSONDecodeError:
                            continue

                # Réécrire le fichier sans les logs de l'utilisateur
                with open(LOGS_FILE, 'w') as f:
                    for log_line in all_logs:
                        f.write(log_line + '\n')

                return True

        except Exception as e:
            print(f"Erreur lors de l'effacement des logs: {e}")
            return False


# Instance globale
_activity_logger = None

def get_activity_logger() -> ActivityLogger:
    """Récupère l'instance globale du logger d'activité"""
    global _activity_logger
    if _activity_logger is None:
        _activity_logger = ActivityLogger()
    return _activity_logger
