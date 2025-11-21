#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}=================================${NC}"
    echo -e "${BLUE}  NAS Securise X25519${NC}"
    echo -e "${BLUE}=================================${NC}"
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}Docker non installe${NC}"
        exit 1
    fi
    if ! docker compose version &> /dev/null && ! command -v docker-compose &> /dev/null; then
        echo -e "${RED}Docker Compose non installe${NC}"
        exit 1
    fi
}

wait_ldap_ready() {
    echo -e "${YELLOW}Attente du demarrage LDAP...${NC}"
    for i in {1..30}; do
        if docker exec nas_ldap ldapsearch -x -H ldap://localhost -b "ou=users,dc=nas,dc=local" -D "cn=admin,dc=nas,dc=local" -w admin &>/dev/null; then
            echo -e "${GREEN}LDAP pret avec utilisateurs${NC}"
            return 0
        fi
        sleep 2
    done
    echo -e "${RED}LDAP non disponible${NC}"
    return 1
}

prepare_dirs() {
    echo -e "${YELLOW}Preparation des repertoires...${NC}"
    mkdir -p user_keys storage temp_uploads temp_downloads
}

start() {
    print_header
    check_docker

    prepare_dirs

    echo -e "\n${YELLOW}Demarrage des services...${NC}"
    docker compose up -d --build

    wait_ldap_ready

    echo -e "\n${GREEN}=================================${NC}"
    echo -e "${GREEN}Services demarres !${NC}"
    echo -e "${GREEN}=================================${NC}"
    echo -e "Interface web: ${BLUE}http://localhost:5000${NC}"
    echo -e "\nUtilisateurs disponibles:"
    echo -e "  alice / alice123"
    echo -e "  bob / bob123"
    echo -e "  charlie / charlie123"
    echo -e "  admin / admin123"
    echo -e "\nCommandes utiles:"
    echo -e "  docker compose logs -f    # Voir les logs"
    echo -e "  docker compose down       # Arreter"
}

stop() {
    print_header
    echo -e "${YELLOW}Arret des services...${NC}"
    docker compose down
    echo -e "${GREEN}Services arretes${NC}"
}

clean() {
    print_header
    echo -e "${RED}Nettoyage complet (donnees incluses)...${NC}"
    docker compose down -v
    rm -rf storage/* temp_uploads/* temp_downloads/*
    echo -e "${GREEN}Nettoyage termine${NC}"
}

case "${1:-start}" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    clean)
        clean
        ;;
    logs)
        docker compose logs -f
        ;;
    *)
        echo "Usage: $0 {start|stop|clean|logs}"
        echo ""
        echo "  start  - Demarre tous les services (defaut)"
        echo "  stop   - Arrete les services"
        echo "  clean  - Arrete et supprime les donnees"
        echo "  logs   - Affiche les logs en temps reel"
        exit 0
        ;;
esac
