#!/bin/bash
set -e
set -o pipefail

echo "========================================"
echo "🧹 Nettoyage complet - R5.A.09"
echo "========================================"

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Fonction pour arrêter tous les compose
stop_all_stacks() {
    log_info "Arrêt de tous les services Docker Compose..."

    local stacks=(traefik dev prod logs ldap monitoring)
    for stack in "${stacks[@]}"; do
        if [ -d "$stack" ] && [ -f "$stack/docker-compose.yml" ]; then
            log_info "Arrêt de la stack $stack..."
            (cd "$stack" && docker compose down -v --remove-orphans 2>/dev/null || true)
        fi
    done

    log_success "Tous les services ont été arrêtés"
}

# Fonction pour supprimer tous les containers
remove_all_containers() {
    log_info "Suppression de tous les containers..."

    # Arrêter tous les containers en cours
    if [ "$(docker ps -q)" ]; then
        docker stop $(docker ps -q) 2>/dev/null || true
    fi

    # Supprimer tous les containers
    if [ "$(docker ps -aq)" ]; then
        docker rm -f $(docker ps -aq) 2>/dev/null || true
    fi

    log_success "Tous les containers supprimés"
}

# Fonction pour supprimer toutes les images
remove_all_images() {
    log_info "Suppression de toutes les images Docker..."

    if [ "$(docker images -q)" ]; then
        docker rmi -f $(docker images -q) 2>/dev/null || true
    fi

    log_success "Toutes les images supprimées"
}

# Fonction pour supprimer tous les volumes
remove_all_volumes() {
    log_info "Suppression de tous les volumes Docker..."

    if [ "$(docker volume ls -q)" ]; then
        docker volume rm $(docker volume ls -q) 2>/dev/null || true
    fi

    log_success "Tous les volumes supprimés"
}

# Fonction pour supprimer tous les réseaux personnalisés
remove_all_networks() {
    log_info "Suppression de tous les réseaux personnalisés..."

    # Récupérer tous les réseaux sauf bridge, host et none
    local networks=$(docker network ls --format "{{.Name}}" | grep -v "^bridge$\|^host$\|^none$" || true)

    if [ ! -z "$networks" ]; then
        echo "$networks" | xargs docker network rm 2>/dev/null || true
    fi

    log_success "Tous les réseaux personnalisés supprimés"
}

# Fonction pour nettoyer le système Docker
clean_docker_system() {
    log_info "Nettoyage complet du système Docker..."

    # Nettoyage système complet
    docker system prune -af --volumes 2>/dev/null || true

    # Nettoyage des builders (si Docker Buildx est utilisé)
    docker builder prune -af 2>/dev/null || true

    log_success "Système Docker nettoyé"
}

# Fonction pour supprimer les données persistantes locales
clean_local_data() {
    log_info "Suppression des données persistantes locales..."

    # Supprimer les dossiers de données s'ils existent
    local data_dirs=("dev/database" "prod/database" "logs/data" "monitoring/data")

    for dir in "${data_dirs[@]}"; do
        if [ -d "$dir" ]; then
            log_info "Suppression de $dir..."
            rm -rf "$dir" 2>/dev/null || true
        fi
    done

    log_success "Données persistantes supprimées"
}

# Fonction pour désinstaller le plugin Loki
remove_loki_plugin() {
    log_info "Suppression du plugin Loki Docker..."

    if docker plugin ls | grep -q "loki"; then
        docker plugin disable loki 2>/dev/null || true
        docker plugin rm loki 2>/dev/null || true
        log_success "Plugin Loki supprimé"
    else
        log_info "Plugin Loki non installé"
    fi
}

# Fonction pour afficher l'état final
show_final_status() {
    log_info "État final du système..."

    echo ""
    echo "📊 Containers restants:"
    docker ps -a --format "table {{.Names}}\t{{.Status}}" 2>/dev/null || echo "Aucun container"

    echo ""
    echo "📦 Images restantes:"
    docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" 2>/dev/null || echo "Aucune image"

    echo ""
    echo "💾 Volumes restants:"
    docker volume ls 2>/dev/null || echo "Aucun volume"

    echo ""
    echo "🌐 Réseaux restants:"
    docker network ls 2>/dev/null || echo "Réseaux par défaut uniquement"

    echo ""
    echo "💽 Espace disque libéré:"
    docker system df 2>/dev/null || true
}

# Fonction principale
main() {
    echo ""
    log_warning "⚠️  ATTENTION: Ce script va supprimer TOUS les containers, images, volumes et réseaux Docker !"
    log_warning "⚠️  Toutes les données seront perdues définitivement !"
    echo ""

    # Demander confirmation à l'utilisateur
    read -p "Êtes-vous sûr de vouloir continuer ? (y/N) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Nettoyage annulé par l'utilisateur"
        exit 0
    fi
    echo ""

    # Nettoyage complet dans l'ordre
    stop_all_stacks
    remove_all_containers
    remove_all_volumes
    remove_all_networks
    remove_all_images
    clean_docker_system
    clean_local_data
    remove_loki_plugin

    # État final
    show_final_status

    echo ""
    echo "========================================"
    log_success "🎉 Nettoyage complet terminé !"
    echo "========================================"
    echo ""
    log_info "Le système Docker est maintenant complètement vide"
    log_info "Vous pouvez relancer ./deploy.sh pour redéployer"
    echo ""
}

# Gestion des erreurs
trap 'log_error "Erreur lors du nettoyage. Continuez manuellement si nécessaire."' ERR

# Exécution
main "$@"