# 🛡️ CernCloud.Nas - NAS Sécurisé avec Chiffrement Zero-Knowledge

**CernCloud.Nas** est une solution de stockage réseau (NAS) sécurisée avec **chiffrement Zero-Knowledge**, garantissant que vos fichiers sont protégés par un chiffrement de bout en bout où le serveur n'a jamais accès à vos clés de chiffrement ou à vos données.

---

## ✨ Fonctionnalités Principales

### 🔐 **Architecture Zero-Knowledge**
- **Chiffrement côté client** : Tout le chiffrement/déchiffrement se fait dans votre navigateur
- **Dérivation de clé basée sur mot de passe** : Votre clé privée est chiffrée avec VOTRE mot de passe via PBKDF2
- **Serveur aveugle** : Le serveur ne connaît jamais votre mot de passe ni votre clé privée
- **Support multi-appareils** avec codes d'autorisation à 6 chiffres

### 🔒 **Sécurité**
- **X25519** (Curve25519) pour l'échange de clés ECDH
- **AES-256-GCM** pour le chiffrement des fichiers
- **Ed25519** pour la vérification de signature des appareils
- **PBKDF2** (100 000 itérations) pour le chiffrement des clés basé sur mot de passe
- **Empreinte d'appareil** pour identification unique
- **Authentification LDAP** pour la gestion des utilisateurs en entreprise

### 📁 **Gestion des Fichiers**
- **Upload/Download** : Interface drag-and-drop pour uploads chiffrés
- **Versionnage** : Versionnage automatique avec capacités de restauration
- **Support des dossiers** : Organisez les fichiers dans des dossiers chiffrés
- **Recherche** : Recherche full-text sur les fichiers chiffrés
- **Quotas** : Limites de stockage par utilisateur

### 👥 **Gestion Multi-Appareils**
- **Autorisation d'appareils** : Ajoutez de nouveaux appareils avec des codes à 6 chiffres
- **Révocation d'appareils** : Supprimez les appareils instantanément
- **Suivi des appareils** : Surveillez tous les appareils connectés avec informations détaillées
- **Appareil maître** : Le premier appareil agit comme ancrage de confiance

### 📊 **Administration**
- **Gestion des utilisateurs** : Administration basée LDAP
- **Logs d'activité** : Pistes d'audit complètes
- **Niveaux de sécurité** : Modes de sécurité flexibles par utilisateur
- **Mode de sécurité global** : Application de politique de sécurité à l'échelle du système

---

## 🚀 Démarrage Rapide

### **Prérequis**
- Docker & Docker Compose
- 2GB RAM minimum
- Linux/macOS/Windows (WSL2)

### **Installation**

#### **Option 1 : Configuration Automatisée (Recommandée)**

La façon la plus simple de démarrer est d'utiliser le script de démarrage fourni :

```bash
# Cloner le dépôt
git clone <url-du-depot>
cd nas

# Lancer la configuration automatisée
./start.sh
```

Le script va automatiquement :
- Créer `.env` depuis `.env.example` si nécessaire
- Générer une `SECRET_KEY` Flask sécurisée
- Construire et démarrer tous les conteneurs Docker
- Afficher l'URL de l'application et les identifiants par défaut

**Démarrage rapide sans confirmation :**
```bash
./start.sh -y
```

#### **Option 2 : Configuration Manuelle**

1. **Cloner le dépôt**
```bash
git clone <url-du-depot>
cd nas
```

2. **Configurer l'environnement**
```bash
cp .env.example .env
nano .env  # Éditer avec vos valeurs
```

3. **Générer la clé secrète Flask**
```bash
python3 scripts/generate_secret.py
# Copier la clé générée dans .env
```

4. **Démarrer les services**
```bash
docker-compose up --build -d
```

5. **Accéder à l'application**
```
http://localhost:5000
```

### **Arrêt et Nettoyage**

Utilisez le script de nettoyage pour différents niveaux de nettoyage :

```bash
# Arrêter les conteneurs (conserve les données)
./scripts/cleanup.sh stop

# Supprimer conteneurs et volumes (efface les données LDAP)
./scripts/cleanup.sh clean

# Nettoyage complet (conteneurs + volumes + images Docker)
./scripts/cleanup.sh purge
```

**Mode interactif** (avec menu) :
```bash
./scripts/cleanup.sh
```

---

## 📋 Configuration

### **Variables d'Environnement (.env)**

```bash
# Flask
SECRET_KEY=<générer-avec-generate_secret.py>
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin

# LDAP
LDAP_ORGANISATION=NAS Company
LDAP_DOMAIN=nas.local
LDAP_BASE_DN=dc=nas,dc=local
LDAP_ADMIN_PASSWORD=admin

# Application
FLASK_PORT=5000
```

### **Première Connexion**

1. Allez sur `http://localhost:5000`
2. Connectez-vous avec les identifiants admin (configurés dans `.env`)
3. Vous serez invité à générer des clés de chiffrement
4. **IMPORTANT** : Mémorisez votre mot de passe maître – il NE PEUT PAS être récupéré !

---

## 💡 Utilisation

### **Configuration Initiale (Premier Appareil)**

1. Connectez-vous à votre compte
2. Créez un **mot de passe maître fort** (chiffre votre clé privée)
3. Cliquez sur "Générer mes clés de chiffrement"
4. Sauvegardez votre mot de passe en sécurité – **la perte signifie perte permanente des données**

### **Ajout d'un Nouvel Appareil**

**Sur le nouvel appareil :**
1. Connectez-vous avec vos identifiants
2. Un **code à 6 chiffres** s'affichera (valide 60 secondes)

**Sur un appareil de confiance :**
1. Cliquez sur "Connexion appareil" dans la sidebar
2. Entrez le code à 6 chiffres affiché sur le nouvel appareil
3. Cliquez sur "Autoriser l'appareil"

**Retour sur le nouvel appareil :**
1. Entrez votre **mot de passe maître**
2. L'appareil est maintenant autorisé et peut déchiffrer vos fichiers

### **Upload de Fichiers**

1. Allez dans "Mes Fichiers"
2. Glissez-déposez des fichiers ou cliquez pour parcourir
3. Les fichiers sont **automatiquement chiffrés** avant upload
4. Le serveur stocke uniquement les données chiffrées

### **Téléchargement de Fichiers**

1. Parcourez jusqu'à votre fichier
2. Cliquez sur "Télécharger"
3. Le fichier est **déchiffré dans votre navigateur**
4. Sauvegardez le fichier déchiffré localement

### **Gestion des Appareils**

1. Allez dans "Connexion appareil" (sidebar)
2. Visualisez tous les appareils connectés
3. Autorisez de nouveaux appareils avec codes à 6 chiffres
4. Révoquez l'accès aux appareils compromis

---

## 🔧 Stack Technique

### **Backend**
- **Flask** : Framework web
- **Python 3.11** : Langage principal
- **LDAP** : Authentification utilisateurs
- **SQLite** : Stockage métadonnées (logs, activité)

### **Frontend**
- **HTML5 + CSS3** : Interface moderne
- **JavaScript (ES6+)** : Logique côté client
- **Web Crypto API** : Chiffrement dans le navigateur
- **Lucide Icons** : Iconographie moderne

### **Chiffrement**
- **X25519** (Curve25519-ECDH) : Échange de clés
- **Ed25519** : Signatures numériques (auth appareils)
- **AES-256-GCM** : Chiffrement symétrique
- **PBKDF2** : Dérivation de clé basée sur mot de passe

### **Infrastructure**
- **Docker** : Conteneurisation
- **Docker Compose** : Orchestration multi-conteneurs
- **OpenLDAP** : Services d'annuaire

---

## 🛡️ Considérations de Sécurité

### **✅ Ce qui est protégé**
- Tous les fichiers sont chiffrés côté client avant upload
- Les clés privées sont chiffrées avec les mots de passe utilisateurs
- Le serveur ne peut déchiffrer aucune donnée utilisateur
- L'autorisation des appareils utilise des signatures cryptographiques

### **⚠️ Limitations**
- **Perte mot de passe = perte données** : Il n'y a AUCUNE récupération de mot de passe
- **Métadonnées visibles** : Noms, tailles et timestamps des fichiers sont stockés non chiffrés
- **Sécurité navigateur** : Le crypto côté client dépend de la sécurité du navigateur

### **🔑 Bonnes Pratiques**
1. Utilisez un **mot de passe maître fort et unique** (20+ caractères)
2. Stockez le mot de passe dans un **gestionnaire de mots de passe**
3. **Révisez régulièrement** les appareils autorisés
4. **Révoquez les appareils** qui ne sont plus nécessaires
5. Gardez des **sauvegardes** des fichiers chiffrés critiques

---

## 📜 Licence

© 2025 CernCloud Systems. Tous droits réservés.

---

## 🆘 Support

### **Problèmes Courants**

**Problème** : "Code invalide" lors de l'autorisation d'appareil  
**Solution** : Les codes expirent après 60 secondes. Générez un nouveau code.

**Problème** : "Clé privée chiffrée introuvable"  
**Solution** : Exécutez la configuration initiale sur `/setup-keys` d'abord.

**Problème** : Les fichiers ne se déchiffrent pas  
**Solution** : Assurez-vous d'utiliser le bon mot de passe maître.

**Problème** : L'authentification LDAP échoue  
**Solution** : Vérifiez la connexion LDAP et les identifiants dans `.env`.

---

## 🔄 Mises à Jour

Récupérer la dernière version :
```bash
git pull origin main
docker-compose down
docker-compose up --build -d
```

---

**Construit avec ❤️ pour la vie privée et la sécurité.**
