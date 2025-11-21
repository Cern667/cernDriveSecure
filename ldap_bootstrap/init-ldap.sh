#\!/bin/bash
# Script d'initialisation LDAP - Importe les utilisateurs si ils n'existent pas

# Attendre que LDAP soit prêt
sleep 2

# Vérifier si l'OU users existe déjà
if ldapsearch -x -H ldap://localhost -b "ou=users,dc=nas,dc=local" -D "cn=admin,dc=nas,dc=local" -w admin >/dev/null 2>&1; then
    echo "Les utilisateurs existent déjà dans LDAP"
    exit 0
fi

echo "Importation des utilisateurs LDAP..."
# Importer les utilisateurs (en sautant la première ligne vide)
tail -n +2 /ldap_bootstrap/01-users.ldif | ldapadd -x -D "cn=admin,dc=nas,dc=local" -w admin

if [ $? -eq 0 ]; then
    echo "✓ Utilisateurs LDAP importés avec succès"
else
    echo "✗ Erreur lors de l'import des utilisateurs LDAP"
    exit 1
fi
