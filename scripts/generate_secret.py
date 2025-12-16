#!/usr/bin/env python3
"""
Script de génération de SECRET_KEY pour Flask

Usage:
    python3 generate_secret.py
"""

import secrets

def generate_secret_key(length=64):
    """Génère une clé secrète aléatoire pour Flask"""
    return secrets.token_hex(length)

if __name__ == "__main__":
    secret = generate_secret_key()
    print("=" * 70)
    print("🔐 FLASK SECRET_KEY GENEREE")
    print("=" * 70)
    print(f"\nSECRET_KEY={secret}\n")
    print("=" * 70)
    print("📝 Copiez cette ligne dans votre fichier .env")
    print("=" * 70)
