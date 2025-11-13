<?php
session_start();

// Logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: /');
    exit;
}

// LDAP connection + login
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username']);
    $password = $_POST['password'];

    $ldapconn = ldap_connect("ldap://ldap-server", 389);
    ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, 3);

    $admin_dn = "cn=admin,dc=td,dc=anthonymoll,dc=fr";
    $admin_password = "adminpassword";

    if (@ldap_bind($ldapconn, $admin_dn, $admin_password)) {
        $escaped_username = ldap_escape($username, "", LDAP_ESCAPE_FILTER);
        $search = ldap_search($ldapconn, "dc=td,dc=anthonymoll,dc=fr", "(|(cn=$escaped_username)(uid=$escaped_username))");

        if ($search) {
            $entries = ldap_get_entries($ldapconn, $search);
            if ($entries['count'] > 0) {
                $user_dn = $entries[0]['dn'];
                if (@ldap_bind($ldapconn, $user_dn, $password)) {
                    $_SESSION['user'] = $username;
                    $_SESSION['dn']   = $user_dn;
                    $_SESSION['is_admin'] = ($user_dn === $admin_dn);
                    header("Location: /"); // reste sur la même page
                    exit;
                } else {
                    $error = "Mot de passe incorrect.";
                }
            } else {
                $error = "Utilisateur non trouvé.";
            }
        } else {
            $error = "Erreur LDAP: " . ldap_error($ldapconn);
        }
    } else {
        $error = "Impossible de se connecter à l’annuaire avec le compte admin.";
    }

    ldap_close($ldapconn);
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Accueil LDAP</title>
<style>
body { font-family: sans-serif; background: #f0f2f5; display: flex; justify-content: center; align-items: center; height: 100vh; margin:0; }
.container { background:#fff; padding:40px; border-radius:12px; box-shadow:0 6px 18px rgba(0,0,0,0.1); width:350px; text-align:center;}
input, button { padding:10px; margin:5px 0; width:100%; }
button { background:#4CAF50; color:white; border:none; border-radius:6px; cursor:pointer; }
button:hover { background:#45a049; }
.error { color:red; margin-bottom:10px;}
</style>
</head>
<body>
<div class="container">
<?php if (!isset($_SESSION['user'])): ?>
    <h1>Connexion</h1>
    <?php if (!empty($error)) echo "<p class='error'>$error</p>"; ?>
    <form method="post">
        <input type="text" name="username" placeholder="Nom d'utilisateur" required>
        <input type="password" name="password" placeholder="Mot de passe" required>
        <button type="submit">Se connecter</button>
    </form>
<?php else: ?>
    <h1>Bonjour <?= htmlspecialchars($_SESSION['user']) ?></h1>
    <?php if ($_SESSION['is_admin']): ?>
        <form action="/import.php" method="get">
            <button type="submit">Aller à l'import CSV</button>
        </form>
    <?php endif; ?>
    <a href="/?logout=1"><button>Déconnexion</button></a>
<?php endif; ?>
</div>
</body>
</html>
