# NAS Securise X25519

Stockage en reseau avec chiffrement zero-knowledge (X25519 + AES-256-GCM) et authentification LDAP.

## Quick Start

```bash
# Cloner et lancer
git clone <repo>
cd nas
./start.sh
```

Acces: http://localhost:5000

## Utilisateurs par defaut

| Utilisateur | Mot de passe |
|-------------|--------------|
| alice       | alice123     |
| bob         | bob123       |
| charlie     | charlie123   |
| admin       | admin123     |

## Commandes

```bash
./start.sh           # Demarrer (defaut)
./start.sh stop      # Arreter
./start.sh clean     # Arreter + supprimer donnees
./start.sh logs      # Voir les logs
```

## Prerequis

- Docker + Docker Compose
- Python 3.9+ (pour generation des cles)

## Architecture

```
Client Flask (5000) --> Serveur Storage (65432)
         |
         v
    LDAP (389)
```

- Le client chiffre les fichiers avec X25519 + AES-256-GCM
- Le serveur stocke uniquement les fichiers chiffres
- Le serveur ne peut jamais dechiffrer les fichiers

## Structure des fichiers

```
nas/
├── dossier_client/      # Application web Flask
├── dossier_server/      # Serveur de stockage
├── client_crypto.py     # Module de chiffrement
├── docker-compose.yml   # Orchestration
├── Dockerfile           # Image Docker (multi-stage)
├── start.sh             # Script principal
├── ldap_bootstrap/      # Utilisateurs LDAP (charge au demarrage)
├── user_keys/           # Cles utilisateurs (genere)
└── storage/             # Fichiers chiffres (genere)
```

## Cles utilisateurs

Les cles sont generees automatiquement au demarrage.

```
user_keys/<user>/
├── private_key.pem   # SECRET - ne jamais partager
└── public_key.pem    # Public
```

**Important**: La perte de la cle privee = perte des fichiers.

## Configuration avancee

Variables d'environnement dans `docker-compose.yml`:

- `FLASK_SECRET_KEY` - Cle de session Flask
- `ADMIN_USERNAME` - Utilisateur admin
- `STORAGE_SERVER_IP` - IP du serveur de stockage
- `FLASK_USE_MOCK_LDAP` - Mode mock sans LDAP

## Depannage

```bash
# Reconstruire les images
docker compose build --no-cache

# Voir les logs d'un service
docker compose logs -f client

# Reinitialiser completement
./start.sh clean
./start.sh
```
