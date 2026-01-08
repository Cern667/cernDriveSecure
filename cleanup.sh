#!/bin/bash
# =============================================================================
# CernCloud.Nas - Cleanup Script
# =============================================================================
# This script offers 3 cleanup levels:
# 1. Simple stop     : Containers stopped, data preserved
# 2. Standard cleanup: Stop + remove volumes
# 3. Full cleanup    : Stop + volumes + Docker images
#
# Usage:
#   ./cleanup.sh              # Interactive mode (menu)
#   ./cleanup.sh stop         # Simple stop (option 1)
#   ./cleanup.sh clean        # Standard cleanup (option 2)
#   ./cleanup.sh purge        # Full cleanup (option 3)
# =============================================================================

set -e  # Exit on error

# Navigate to project directory
cd "$(dirname "$0")"

echo "======================================================================"
echo "CernCloud.Nas - Cleanup Script"
echo "======================================================================"
echo ""

# Check if automated mode (with argument)
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
            echo "ERROR: Invalid argument: $1"
            echo ""
            echo "Usage:"
            echo "  ./cleanup.sh stop   # Simple stop"
            echo "  ./cleanup.sh clean  # Standard cleanup (with confirmation)"
            echo "  ./cleanup.sh purge  # Full cleanup (with confirmation)"
            exit 1
            ;;
    esac
else
    # Interactive mode: show menu
    echo "Choose cleanup level:"
    echo ""
    echo "1) Stop containers (data preserved)"
    echo "2) Standard cleanup (stop + remove volumes)"
    echo "3) Full cleanup (stop + volumes + Docker images)"
    echo "4) Force delete images only"
    echo "5) Cancel"
    echo ""

    read -p "Your choice (1-5): " choice
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

case $choice in
    1)
        echo ""
        echo "======================================================================"
        echo "Stopping containers..."
        echo "======================================================================"
        $DOCKER_COMPOSE_CMD down

        echo ""
        echo "SUCCESS: Containers stopped."
        echo "INFO: Volumes preserved (data safe)"
        echo ""
        echo "To restart: ./start.sh or $DOCKER_COMPOSE_CMD up -d"
        ;;

    2)
        echo ""
        read -p "WARNING: This will delete ALL LDAP data. Continue? (y/N) " -r
        echo
        if [[ ! $REPLY =~ ^[OoYy]$ ]]; then
            echo "Cancelled."
            exit 0
        fi

        echo ""
        echo "======================================================================"
        echo "Standard cleanup (containers + volumes)..."
        echo "======================================================================"
        $DOCKER_COMPOSE_CMD down -v

        echo ""
        echo "SUCCESS: Containers and volumes removed."
        echo "INFO: Local data preserved (storage/, user_keys/)"
        echo ""
        echo "To restart: ./start.sh or $DOCKER_COMPOSE_CMD up -d"
        ;;

    3)
        echo ""
        read -p "WARNING: This will delete ALL data AND Docker images. Continue? (y/N) " -r
        echo
        if [[ ! $REPLY =~ ^[OoYy]$ ]]; then
            echo "Cancelled."
            exit 0
        fi

        echo ""
        echo "======================================================================"
        echo "Full cleanup (containers + volumes + images)..."
        echo "======================================================================"

        # Stop and remove everything including built images (local)
        $DOCKER_COMPOSE_CMD down -v --rmi local

        # Extra safety: remove images by project label (works if project name matches folder)
        PROJECT_NAME=$(basename "$(pwd)")
        echo "Cleaning up remaining images for project: $PROJECT_NAME..."
        docker image ls --filter label=com.docker.compose.project=$PROJECT_NAME -q | xargs -r docker rmi -f 2>/dev/null || true

        # Fallback: Remove specific known names
        echo "Removing known image names..."
        docker rmi nas-client nas-server nas_client nas_server 2>/dev/null || true

        # Remove unused images
        echo ""
        echo "Cleaning unused images..."
        docker image prune -f

        echo ""
        echo "SUCCESS: Full cleanup completed."
        echo ""
        echo "Removed:"
        echo "  - Containers"
        echo "  - Docker volumes"
        echo "  - Docker images (built locally)"
        echo ""
        echo "INFO: Local data preserved (storage/, user_keys/)"
        echo ""
        echo "NOTE: On next startup, images will be rebuilt."
        echo "To restart: ./start.sh or $DOCKER_COMPOSE_CMD up --build -d"
        ;;

    4)
        echo ""
        echo "======================================================================"
        echo "Force removing NAS images..."
        echo "======================================================================"
        
        # Remove by label
        PROJECT_NAME=$(basename "$(pwd)")
        docker image ls --filter label=com.docker.compose.project=$PROJECT_NAME -q | xargs -r docker rmi -f 2>/dev/null || true
        
        # Remove by name
        docker rmi nas-client nas-server nas_client nas_server 2>/dev/null || true
        
        echo "✅ Images removed."
        ;;

    5)
        echo "Cancelled."
        exit 0
        ;;

    *)
        echo "ERROR: Invalid choice."
        exit 1
        ;;
esac

echo ""
echo "======================================================================"
echo "Cleanup completed"
echo "======================================================================"
