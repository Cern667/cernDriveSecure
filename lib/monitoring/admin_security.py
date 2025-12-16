#!/usr/bin/env python3
"""
Gestion du mode de sécurité global
Contrôlé uniquement par l'administrateur
"""

import os
import shutil
from typing import Dict, List
from dotenv import load_dotenv, set_key
from activity_logger import get_activity_logger

ENV_FILE = '.env'
SECURITY_MODE_KEY = 'SECURITY_MODE'

def get_current_mode() -> str:
    """Récupère le mode actuel depuis .env"""
    load_dotenv()
    return os.getenv(SECURITY_MODE_KEY, 'normal')

def get_users_with_files() -> List[str]:
    """Liste les utilisateurs ayant des fichiers"""
    storage_dir = '/app/storage'
    users = []
    
    if not os.path.exists(storage_dir):
        return users
    
    for username in os.listdir(storage_dir):
        user_path = os.path.join(storage_dir, username)
        if os.path.isdir(user_path):
            # Vérifier si contient des fichiers
            has_files = False
            for root, dirs, files in os.walk(user_path):
                if files:
                    has_files = True
                    break
            if has_files:
                users.append(username)
    
    return users

def purge_all_data():
    """Supprime tous les fichiers et clés de tous les utilisateurs"""
    # 1. Purge storage
    storage_dir = '/app/storage'
    if os.path.exists(storage_dir):
        for username in os.listdir(storage_dir):
            user_path = os.path.join(storage_dir, username)
            if os.path.isdir(user_path):
                # Supprimer tout sauf le dossier lui-même
                for item in os.listdir(user_path):
                    item_path = os.path.join(user_path, item)
                    if os.path.isfile(item_path):
                        os.remove(item_path)
                    elif os.path.isdir(item_path):
                        shutil.rmtree(item_path)
    
    # 2. Purge user_keys (clés privées mode actuel)
    user_keys_dir = '/app/user_keys'
    if os.path.exists(user_keys_dir):
        shutil.rmtree(user_keys_dir)
        os.makedirs(user_keys_dir)
    
    # 3. Purge public_keys (mode ZK)
    public_keys_dir = '/app/public_keys'
    if os.path.exists(public_keys_dir):
        shutil.rmtree(public_keys_dir)
        os.makedirs(public_keys_dir)

def change_security_mode(new_mode: str, admin_username: str, force_purge: bool = False) -> Dict:
    """
    Change le mode de sécurité global
    
    Args:
        new_mode: 'normal' ou 'maximum'
        admin_username: Nom de l'admin effectuant le changement
        force_purge: Si True, purge sans vérification
    
    Returns:
        {
            'success': bool,
            'action_required': str | None,
            'affected_users': list,
            'message': str
        }
    """
    if new_mode not in ['normal', 'maximum']:
        return {
            'success': False,
            'message': 'Mode invalide. Utilisez "normal" ou "maximum".'
        }
    
    current_mode = get_current_mode()
    
    if current_mode == new_mode:
        return {
            'success': True,
            'message': f'Déjà en mode {new_mode}.'
        }
    
    # Vérifier fichiers existants
    users_with_files = get_users_with_files()
    
    if len(users_with_files) > 0 and not force_purge:
        return {
            'success': False,
            'action_required': 'confirm_purge',
            'affected_users': users_with_files,
            'message': f'{len(users_with_files)} utilisateur(s) ont des fichiers. Confirmation requise.'
        }
    
    # Logger l'action
    logger = get_activity_logger()
    
    # Purge si nécessaire
    if len(users_with_files) > 0:
        purge_all_data()
        logger.log_activity(
            admin_username, 
            'SECURITY_MODE_CHANGE_PURGE', 
            '127.0.0.1',
            'SUCCESS',
            f'Mode changé: {current_mode} → {new_mode}. {len(users_with_files)} utilisateurs purgés: {", ".join(users_with_files)}'
        )
    
    # Mise à jour .env
    set_key(ENV_FILE, SECURITY_MODE_KEY, new_mode)
    
    logger.log_activity(
        admin_username,
        'SECURITY_MODE_CHANGE',
        '127.0.0.1',
        'SUCCESS',
        f'Mode de sécurité changé: {current_mode} → {new_mode}'
    )
    
    return {
        'success': True,
        'message': f'Mode changé vers {new_mode}. {len(users_with_files)} utilisateur(s) purgé(s).',
        'purged_users': users_with_files
    }
