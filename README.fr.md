# CernCloud.Nas - Stockage Réseau à Connaissance Nulle

Système NAS sécurisé avec chiffrement zero-knowledge. Les fichiers sont chiffrés dans le navigateur avant l'upload, garantissant que le serveur n'a jamais accès aux clés de chiffrement ou aux données en clair.

[English](README.md)

---

## Fonctionnalités Principales

- **Architecture Zero-Knowledge**: Le serveur ne voit jamais les données déchiffrées
- **Chiffrement Client**: AES-256-GCM + X25519/EC P-256 ECDH
- **Multi-Appareils**: Autorisation cryptographique des nouveaux appareils
- **Versioning**: Historique automatique avec restauration
- **Deux Modes de Sécurité**:
  - Standard: EC P-256 avec déchiffrement serveur
  - Maximum: X25519 avec déchiffrement uniquement côté client
- **Authentification LDAP**: Annuaire utilisateur
- **Journalisation**: Piste d'audit complète

---

## Démarrage Rapide

### Prérequis
- Docker & Docker Compose
- 2GB RAM minimum
- Linux/macOS/Windows (WSL2)

### Installation

**Option 1: Docker Compose (Recommandé)**

```bash
git clone https://github.com/Nolan667/cernDriveSecure.git
cd nas
cp .env.example .env
nano .env  # Éditer SECRET_KEY et mots de passe
docker-compose up -d
```

Accès: `http://localhost:5000`

**Option 2: Script Automatisé**

```bash
./start.sh  # Crée .env, génère SECRET_KEY, démarre conteneurs
```

### Configuration

Éditer `.env` avant démarrage:

```bash
# Obligatoire - Générer avec: python3 scripts/generate_secret.py
SECRET_KEY=votre-clé-générée

# Identifiants admin (À CHANGER)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin

# Configuration LDAP
LDAP_ORGANISATION=Votre Entreprise
LDAP_DOMAIN=nas.local
LDAP_BASE_DN=dc=nas,dc=local
LDAP_ADMIN_PASSWORD=admin

# Application
FLASK_PORT=5000
```

**Note de Sécurité**: Ne jamais committer `.env`. Exclu via `.gitignore`.

### Nettoyage

```bash
./scripts/cleanup.sh stop   # Arrêt conteneurs (garde données)
./scripts/cleanup.sh clean  # Suppression conteneurs + volumes
./scripts/cleanup.sh purge  # Nettoyage complet incluant images
```

---

## Architecture

### Stack
- **Frontend**: JS Vanilla avec Web Crypto API
- **Backend**: Python 3.11 + Flask
- **Stockage**: Serveur TCP socket (port 65432)
- **Authentification**: OpenLDAP
- **Chiffrement**: X25519/EC P-256 + AES-256-GCM

### Composants

**Services Docker**:
- `ldap`: Annuaire OpenLDAP (port 389)
- `server`: Serveur de stockage fichiers chiffrés
- `client`: Interface web Flask (port 5000)

**Modules Clés**:
- `lib/auth/`: Gestionnaire appareils, niveaux sécurité, autorisation QR
- `lib/crypto/`: Chiffrement X25519/EC, gestion clés
- `lib/monitoring/`: Journalisation activités, sécurité admin
- `web_client/`: App Flask, templates, crypto client

### Flux de Chiffrement

**Mode Standard (EC P-256)**:
1. Génération paire de clés EC P-256 dans navigateur
2. Clé privée chiffrée avec mot de passe (PBKDF2, 100k itérations)
3. Clé privée chiffrée stockée sur serveur
4. Fichiers chiffrés avec clé AES-256 aléatoire
5. Clé AES chiffrée avec clé publique destinataire (ECDH)
6. Serveur déchiffre fichiers avec clé privée stockée

**Mode Maximum (X25519)**:
1. Même génération paire de clés mais avec X25519
2. Clé privée JAMAIS envoyée au serveur
3. Déchiffrement uniquement côté client dans navigateur
4. Mot de passe requis pour chaque session de déchiffrement

### Garanties Zero-Knowledge

**Serveur Stocke**:
- Clés privées chiffrées (protégées par mot de passe)
- Clés publiques
- Fichiers chiffrés (.enc)
- Clés AES chiffrées (.key)
- Métadonnées (noms fichiers, timestamps)

**Serveur NE VOIT JAMAIS**:
- Mots de passe
- Clés privées en clair
- Fichiers en clair
- Clés AES en clair

**ATTENTION**: Perte mot de passe = perte permanente données. Aucune récupération possible.

---

## Utilisation

### Configuration Initiale (Premier Appareil)

1. Connexion sur `http://localhost:5000`
2. Cliquer "Générer mes clés de chiffrement"
3. Choisir niveau sécurité (Standard ou Maximum)
4. Créer mot de passe maître fort
5. Sauvegarder mot de passe - irrécupérable

### Ajout Nouvel Appareil

**Sur nouvel appareil**:
1. Connexion avec identifiants
2. Code à 6 chiffres affiché (valide 60 secondes)

**Sur appareil de confiance**:
1. Aller dans "Connexion appareil"
2. Entrer code à 6 chiffres
3. Approuver autorisation

**Retour sur nouvel appareil**:
1. Entrer mot de passe maître
2. Appareil autorisé

### Opérations Fichiers

**Upload**:
1. Aller dans "Mes Fichiers"
2. Glisser-déposer ou sélectionner fichiers
3. Fichiers chiffrés automatiquement avant upload

**Téléchargement**:
- **Mode standard**: Clic télécharger (déchiffre sur serveur)
- **Mode maximum**: Entrer mot de passe (déchiffre dans navigateur)

**Versioning**:
- Fichiers automatiquement versionnés lors écrasement
- Voir versions dans onglet "Versions"
- Télécharger ou restaurer versions précédentes

---

## Sécurité

### Bonnes Pratiques

1. **Mots de passe forts**: Mot de passe maître chiffre clé privée
2. **Activer mode Maximum**: Pour sécurité maximale (côté client uniquement)
3. **Sauvegarder mots de passe**: Utiliser gestionnaire mots de passe
4. **Changer identifiants par défaut**: Modifier `ADMIN_PASSWORD` et `LDAP_ADMIN_PASSWORD`
5. **Générer SECRET_KEY forte**: Utiliser `scripts/generate_secret.py`
6. **Révoquer appareils compromis**: Depuis interface "Connexion appareil"

### Modèle de Menace

**Protégé Contre**:
- Compromission serveur (données chiffrées)
- Interception réseau (TLS recommandé)
- Fuites base de données (clés chiffrées)
- Accès appareil non autorisé (autorisation cryptographique)

**Non Protégé Contre**:
- Malware côté client (peut voler mot de passe lors saisie)
- Accès physique appareil déverrouillé
- Compromission mot de passe (permet déchiffrement)
- Vulnérabilités navigateur

### Déploiement Production

1. Utiliser HTTPS/TLS pour toutes connexions
2. Changer tous mots de passe par défaut dans `.env`
3. Générer `SECRET_KEY` unique par déploiement
4. Utiliser `LDAP_ADMIN_PASSWORD` fort
5. Implémenter isolation réseau (règles pare-feu)
6. Sauvegardes régulières données chiffrées
7. Surveiller journaux activités pour comportements suspects

---

## Développement

### Structure Fichiers

```
nas/
├── docker-compose.yml      # Orchestration services
├── Dockerfile              # Build multi-étapes
├── .env.example            # Template configuration
├── start.sh                # Déploiement automatisé
├── scripts/
│   └── cleanup.sh          # Utilitaire nettoyage
├── lib/
│   ├── auth/               # Authentification & appareils
│   ├── crypto/             # Modules chiffrement
│   └── monitoring/         # Journalisation
├── web_client/
│   ├── app.py              # Application Flask
│   ├── static/js/          # Crypto client
│   └── templates/          # Templates HTML
├── storage_server/
│   └── server.py           # Serveur stockage TCP
└── ldap_bootstrap/
    └── 01-users.ldif       # Utilisateurs LDAP initiaux
```

### Commandes

```bash
# Voir journaux
docker-compose logs -f
docker-compose logs -f client
docker-compose logs -f server

# Redémarrer service
docker-compose restart client

# Rebuild après changements code
docker-compose up --build -d

# Accès shell conteneur
docker exec -it nas_client /bin/bash
```

### Ajout Utilisateurs

Éditer `ldap_bootstrap/01-users.ldif` et redémarrer:

```bash
docker-compose down
docker-compose up -d
```

---

## Dépannage

**"Code invalide" lors autorisation appareil**:
- Codes expirent après 60 secondes
- Vérifier synchronisation horloge système
- Régénérer code si expiré

**Fichiers ne se déchiffrent pas**:
- Vérifier mot de passe correct
- Vérifier niveau sécurité correspond au type de clé
- Consulter console navigateur pour erreurs

**Échec authentification LDAP**:
- Vérifier conteneur LDAP: `docker-compose ps`
- Vérifier identifiants dans `.env`
- Tester bind LDAP: `docker exec nas_ldap ldapsearch -x -H ldap://localhost`

**Connexion serveur stockage refusée**:
- Vérifier journaux serveur: `docker-compose logs server`
- Vérifier `STORAGE_SERVER_IP` et `STORAGE_SERVER_PORT` dans `.env`

---

## Licence

[Votre Licence Ici]

## Contribution

[Vos Directives de Contribution Ici]
