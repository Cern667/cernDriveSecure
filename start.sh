#!/bin/bash
# =============================================================================
# 🚀 CernCloud.Nas - Script de Démarrage Automatique
# =============================================================================
# Ce script :
# 1. Crée le .env depuis .env.example (si nécessaire)
# 2. Génère automatiquement un SECRET_KEY Flask sécurisé
# 3. Lance docker-compose avec toute la stack
# =============================================================================

set -e  # Exit on error

# Option pour skip la confirmation
AUTO_YES=false
if [[ "$1" == "-y" ]] || [[ "$1" == "--yes" ]]; then
    AUTO_YES=true
fi

echo "======================================================================"
echo "🚀 CernCloud.Nas - Démarrage Automatique"
echo "======================================================================"
echo ""

# Vérifier si Docker est installé
if ! command -v docker &> /dev/null; then
    echo "❌ Docker n'est pas installé. Veuillez installer Docker et Docker Compose."
    exit 1
fi

# Détection de la commande Docker Compose
if command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE_CMD="docker-compose"
elif docker compose version &> /dev/null; then
    DOCKER_COMPOSE_CMD="docker compose"
else
    echo "❌ Docker Compose n'est pas installé (ni 'docker-compose' ni 'docker compose')."
    exit 1
fi

# Vérifier si .env.example existe
if [ ! -f .env.example ]; then
    echo "❌ Fichier .env.example introuvable !"
    echo "   Ce fichier est nécessaire pour initialiser la configuration."
    exit 1
fi

# Créer .env depuis .env.example si nécessaire
if [ ! -f .env ]; then
    echo "📝 Fichier .env introuvable. Création depuis .env.example..."
    cp .env.example .env
    echo "✅ Fichier .env créé"
else
    echo "✅ Fichier .env existant trouvé"
fi

# Lire le .env actuel
source .env

# Vérifier si SECRET_KEY doit être générée
if [ -z "$SECRET_KEY" ] || [ "$SECRET_KEY" == "change-me-in-production-use-generate-secret-script" ]; then
    echo ""
    echo "🔐 Génération d'une nouvelle SECRET_KEY Flask sécurisée..."

    # Générer une clé de 128 caractères hexadécimaux (64 bytes)
    NEW_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(64))")

    # Remplacer dans le .env
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s|^SECRET_KEY=.*|SECRET_KEY=$NEW_SECRET|" .env
    else
        # Linux
        sed -i "s|^SECRET_KEY=.*|SECRET_KEY=$NEW_SECRET|" .env
    fi

    echo "✅ SECRET_KEY générée et sauvegardée dans .env"
    # Recharger le .env après modification
    source .env
else
    echo "✅ SECRET_KEY déjà configurée"
fi

echo ""
echo "======================================================================"
echo "📋 Configuration détectée (.env)"
echo "======================================================================"
echo "🔹 ADMIN_USERNAME:      $ADMIN_USERNAME"
echo "🔹 LDAP_ORGANISATION:   $LDAP_ORGANISATION"
echo "🔹 LDAP_DOMAIN:         $LDAP_DOMAIN"
echo "🔹 LDAP_BASE_DN:        $LDAP_BASE_DN"
echo "🔹 FLASK_PORT:          $FLASK_PORT"
echo "🔹 SECRET_KEY:          ${SECRET_KEY:0:20}... (masqué pour sécurité)"
echo ""

if [ "$AUTO_YES" = false ]; then
    read -p "⚙️  Voulez-vous continuer avec cette configuration ? (o/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[OoYy]$ ]]; then
        echo "❌ Démarrage annulé."
        echo "   Pour modifier : éditez le fichier .env puis relancez ce script"
        echo "   Pour lancer sans confirmation : ./start.sh -y"
        exit 0
    fi
fi

echo ""
echo "======================================================================"
echo "🐳 Arrêt des conteneurs existants (si présents)..."
echo "======================================================================"
$DOCKER_COMPOSE_CMD down 2>/dev/null || true

echo ""
echo "======================================================================"
echo "🏗️  Build et démarrage des conteneurs..."
echo "======================================================================"
$DOCKER_COMPOSE_CMD up --build -d

# Attendre que les services démarrent
echo ""
echo "⏳ Attente du démarrage des services..."
sleep 5

# Vérifier le statut
echo ""
echo "======================================================================"
echo "📊 Statut des conteneurs"
echo "======================================================================"
$DOCKER_COMPOSE_CMD ps

echo ""
echo "======================================================================"
echo "✅ Démarrage terminé avec succès !"
echo "======================================================================"
echo ""
echo "🌐 Accédez à l'application web :"
echo "   👉 http://localhost:$FLASK_PORT"
echo ""
echo "👤 Identifiants par défaut :"
echo "   Username : $ADMIN_USERNAME"
echo "   Password : $ADMIN_PASSWORD"
echo ""
echo "📋 Commandes utiles :"
echo "   📝 Voir les logs        : $DOCKER_COMPOSE_CMD logs -f"
echo "   📝 Logs d'un service    : $DOCKER_COMPOSE_CMD logs -f [ldap|server|client]"
echo "   📊 Statut des services  : $DOCKER_COMPOSE_CMD ps"
echo "   🛑 Arrêter/nettoyer     : ./cleanup.sh"
echo ""
echo "🔧 Services lancés :"
echo "   ✅ LDAP Server     (port 389)"
echo "   ✅ Storage Server  (port 65432)"
echo "   ✅ Web Client      (port $FLASK_PORT)"
echo ""
echo "======================================================================"
echo "💡 Astuce : Lancez avec './start.sh -y' pour skip la confirmation"
echo "======================================================================"
