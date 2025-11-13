<?php
// Fonctions utilitaires pour LDAP

/**
 * Connexion et bind LDAP
 * @param string $dn DN complet de l'utilisateur/admin
 * @param string $password mot de passe
 * @return resource $ldapconn
 * @throws Exception si impossible de binder
 */
function ldap_connect_bind($dn, $password) {
    $ldapconn = ldap_connect("ldap://ldap-server", 389);
    if (!$ldapconn) {
        throw new Exception("Impossible de se connecter au serveur LDAP");
    }
    ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, 3);
    ldap_set_option($ldapconn, LDAP_OPT_NETWORK_TIMEOUT, 10);

    if (!@ldap_bind($ldapconn, $dn, $password)) {
        throw new Exception("Echec de connexion LDAP avec $dn : " . ldap_error($ldapconn));
    }
    return $ldapconn;
}

/**
 * Vérifie si un DN est membre d'un groupe LDAP
 * @param resource $ldapconn
 * @param string $user_dn
 * @param string $group_dn
 * @return bool
 */
function ldap_is_member_of($ldapconn, $user_dn, $group_dn) {
    $filter = "(member=$user_dn)";
    $sr = ldap_search($ldapconn, $group_dn, $filter, ["dn"]);
    if (!$sr) return false;
    $entries = ldap_get_entries($ldapconn, $sr);
    return $entries['count'] > 0;
}

/**
 * Hash SSHA pour mot de passe LDAP
 * @param string $password
 * @return string
 */
function ldap_hash_password($password) {
    $salt = random_bytes(4);
    $hash = sha1($password . $salt, true) . $salt;
    return '{SSHA}' . base64_encode($hash);
}
