# Configuration LDAP (hors Docker)

Ce dossier contient des fichiers d’exemple pour initialiser un annuaire LDAP compatible avec l’application Flask.

## Hypothèses par défaut
- Base DN: `dc=mondomaine,dc=com`
- OU des utilisateurs: `ou=users,dc=mondomaine,dc=com`
- Compte de service (bind) pour les recherches: `cn=admin,dc=mondomaine,dc=com` (mot de passe: `admin`)
- Hôte: `ldap://localhost:389` (modifiable via `.env`)

## Fichiers
- `users.ldif` — Arbre de base + compte de service `cn=admin` + un utilisateur de test `uid=alice`.

## Mise en place rapide (OpenLDAP)
1. Installez un serveur LDAP local (OpenLDAP, ApacheDS, ou équivalent).
2. Démarrez le serveur sur `localhost:389`.
3. Importez le fichier `users.ldif` avec votre outil LDAP (ex: `ldapadd` ou Apache Directory Studio).
   - Exemple (OpenLDAP):
     ```
     ldapadd -x -D "cn=admin,dc=mondomaine,dc=com" -w admin -f users.ldif
     ```
4. Vérifiez que vous pouvez vous connecter avec l’utilisateur de test:
   - DN: `uid=alice,ou=users,dc=mondomaine,dc=com`
   - Mot de passe: `alice123`

## Configuration côté application
Les variables sont dans `.env`:
- `FLASK_LDAP_HOST=ldap://localhost:389`
- `FLASK_LDAP_BASE_DN=dc=mondomaine,dc=com`
- `FLASK_LDAP_USER_DN=ou=users`
- `FLASK_LDAP_BIND_USER_DN=cn=admin,dc=mondomaine,dc=com`
- `FLASK_LDAP_BIND_USER_PASSWORD=admin`

Adaptez ces valeurs pour correspondre à votre annuaire réel si besoin.