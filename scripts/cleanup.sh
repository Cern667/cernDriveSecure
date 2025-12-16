#!/bin/bash
# =============================================================================
# 🧹 CernCloud.Nas - Script de Nettoyage
# =============================================================================
# Ce script propose 3 niveaux de nettoyage :
# 1. Arrêt simple      : Conteneurs arrêtés, données conservées
# 2. Nettoyage standard: Arrêt + suppression volumes
# 3. Nettoyage complet : Arrêt + volumes + images Docker
#
# Usage:
#   ./cleanup.sh              # Mode interactif (menu)
#   ./cleanup.sh stop         # Arrêt simple (option 1)
#   ./cleanup.sh clean        # Nettoyage standard (option 2)
#   ./cleanup.sh purge        # Nettoyage complet (option 3)
# =============================================================================

set -e  # Exit on error

# Se déplacer dans le répertoire du projet
cd "$(dirname "$0")/.."

echo "======================================================================"
echo "🧹 CernCloud.Nas - Script de Nettoyage"
echo "======================================================================"
echo ""

# Vérifier si mode automatique (avec argument)
AUTO_MODE=false
if [ $# -gt 0 ]; then
    AUTO_MODE=true
    case "$1" in
        stop)
            choice=1
            ;;
        clean)
            choice=2
            ;;
        purge|full)
            choice=3
            ;;
        *)
            echo "❌ Argument invalide : $1"
            echo ""
            echo "Usage:"
            echo "  ./cleanup.sh stop   # Arrêt simple"
            echo "  ./cleanup.sh clean  # Nettoyage standard (avec confirmation)"
            echo "  ./cleanup.sh purge  # Nettoyage complet (avec confirmation)"
            exit 1
            ;;
    esac
else
    # Mode interactif : afficher le menu
    echo "Choisissez le niveau de nettoyage :"
    echo ""
    echo "1) 🛑 Arrêt simple (conteneurs arrêtés, données conservées)"
    echo "2) 🗑️  Nettoyage standard (arrêt + suppression volumes)"
    echo "3) 💥 Nettoyage complet (arrêt + volumes + images Docker)"
    echo "4) ❌ Annuler"
    echo ""

    read -p "Votre choix (1-4): " choice
fi

case $choice in
    1)
        echo ""
        echo "======================================================================"
        echo "🛑 Arrêt des conteneurs..."
        echo "======================================================================"
        docker-compose down
        
        echo ""
        echo "✅ Conteneurs arrêtés."
        echo "📦 Volumes conservés (données préservées)"
        echo ""
        echo "Pour redémarrer : ./start.sh"
        ;;
        
    2)
        echo ""
        read -p "⚠️  ATTENTION: Cela supprimera TOUTES les données LDAP. Continuer ? (o/N) " -r
        echo
        if [[ ! $REPLY =~ ^[OoYy]$ ]]; then
            echo "❌ Annulé."
            exit 0
        fi
        
        echo ""
        echo "======================================================================"
        echo "🗑️  Nettoyage standard (conteneurs + volumes)..."
        echo "======================================================================"
        docker-compose down -v
        
        echo ""
        echo "✅ Conteneurs et volumes supprimés."
        echo "📂 Données locales préservées (storage/, user_keys/)"
        echo ""
        echo "Pour redémarrer : ./start.sh"
        ;;
        
    3)
        echo ""
        read -p "💥 ATTENTION: Cela supprimera TOUTES les données ET les images Docker. Continuer ? (o/N) " -r
        echo
        if [[ ! $REPLY =~ ^[OoYy]$ ]]; then
            echo "❌ Annulé."
            exit 0
        fi
        
        echo ""
        echo "======================================================================"
        echo "💥 Nettoyage complet (conteneurs + volumes + images)..."
        echo "======================================================================"
        
        # Arrêter et supprimer tout
        docker-compose down -v
        
        # Supprimer les images construites
        echo ""
        echo "🗑️  Suppression des images Docker..."
        docker rmi nas_client nas_server 2>/dev/null || true
        
        # Supprimer les images inutilisées
        echo ""
        echo "🧹 Nettoyage des images inutilisées..."
        docker image prune -f
        
        echo ""
        echo "✅ Nettoyage complet terminé."
        echo ""
        echo "Supprimé :"
        echo "  - ✅ Conteneurs"
        echo "  - ✅ Volumes Docker"
        echo "  - ✅ Images Docker (nas_client, nas_server)"
        echo ""
        echo "📂 Données locales préservées (storage/, user_keys/)"
        echo ""
        echo "⚠️  Note: Au prochain démarrage, les images seront reconstruites."
        echo "Pour redémarrer : ./start.sh"
        ;;
        
    4)
        echo "❌ Annulé."
        exit 0
        ;;
        
    *)
        echo "❌ Choix invalide."
        exit 1
        ;;
esac

echo ""
echo "======================================================================"
echo "🏁 Nettoyage terminé"
echo "======================================================================"
