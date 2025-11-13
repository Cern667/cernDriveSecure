<?php
// ⚠ Aucune ligne ou espace avant ce <?php

ini_set('session.cookie_lifetime', 3600);
ini_set('session.gc_maxlifetime', 3600);
session_start();

require_once __DIR__ . "/includes/ldap.php"; // chemin correct

// Vérification admin
if (!isset($_SESSION['user']) || empty($_SESSION['is_admin']) || $_SESSION['is_admin'] !== true) {
    header('HTTP/1.1 403 Forbidden');
    echo "Accès interdit. Seul l’administrateur peut importer.";
    exit;
}

$success = [];
$errors = [];

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $errors[] = "Token CSRF invalide.";
    } elseif (!isset($_FILES['csv']) || $_FILES['csv']['error'] !== UPLOAD_ERR_OK) {
        $errors[] = "Erreur d’upload du CSV.";
    } else {
        try {
            $admin_dn = "cn=admin,dc=td,dc=anthonymoll,dc=fr";
            $admin_password = "adminpassword";
            $ldap = ldap_connect_bind($admin_dn, $admin_password);

            $handle = fopen($_FILES['csv']['tmp_name'], "r");
            $header = fgetcsv($handle, 0, ";");

            while (($row = fgetcsv($handle, 0, ";")) !== false) {
                $data = array_combine($header, $row);
                if (!$data) {
                    $errors[] = "Ligne invalide : " . implode(";", $row);
                    continue;
                }

                $dn = "cn={$data['uid']},ou=users,dc=td,dc=anthonymoll,dc=fr";
                $entry = [
                    "objectClass" => ["inetOrgPerson"],
                    "cn"          => $data['uid'],
                    "sn"          => $data['sn'],
                    "givenName"   => $data['cn'],
                    "displayName" => $data['cn'] . " " . $data['sn'],
                    "userPassword"=> ldap_hash_password($data['password']),
                ];

                if (@ldap_add($ldap, $dn, $entry)) {
                    $success[] = "Ajouté: {$data['uid']}";
                } else {
                    $errors[] = "Erreur {$data['uid']} : " . ldap_error($ldap);
                }
            }

            fclose($handle);
            ldap_close($ldap);
        } catch (Exception $e) {
            $errors[] = $e->getMessage();
        }
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Import CSV (Admin)</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f4f7f8;
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 700px;
            margin: 50px auto;
            background: #fff;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 6px 18px rgba(0,0,0,0.1);
        }
        h1 { text-align: center; color: #333; }
        a { text-decoration: none; color: #555; margin-bottom: 20px; display: inline-block; }
        form { display: flex; flex-direction: column; gap: 15px; }
        input[type="file"] { padding: 10px; border: 1px solid #ccc; border-radius: 6px; width: 100%; }
        button { padding: 12px; background: #4CAF50; color: white; border: none; border-radius: 8px; font-size: 16px; cursor: pointer; }
        button:hover { background: #45a049; }
        .success { color: green; margin-bottom: 10px; }
        .error { color: red; margin-bottom: 10px; }
        pre { background: #eee; padding: 10px; border-radius: 6px; overflow-x: auto; }
    </style>
</head>
<body>
<div class="container">
    <h1>Import CSV (Admin)</h1>
    <a href="/index.php">⬅ Retour</a>

    <?php foreach ($success as $msg): ?>
        <p class="success"><?= htmlspecialchars($msg) ?></p>
    <?php endforeach; ?>

    <?php foreach ($errors as $err): ?>
        <p class="error"><?= htmlspecialchars($err) ?></p>
    <?php endforeach; ?>

    <form method="post" enctype="multipart/form-data">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']); ?>">
        <label>Fichier CSV:</label>
        <input type="file" name="csv" accept=".csv" required>
        <button type="submit">Importer</button>
    </form>

    <h3>Format attendu (séparateur ;)</h3>
    <pre>
uid;cn;sn;mail;ine;password
alice;Alice;Dupont;alice@example.com;;motdepasse1
bob;Bob;Martin;bob@example.com;;motdepasse2
charlie;Charlie;Brown;charlie@example.com;;motdepasse3
david;David;Smith;david@example.com;;motdepasse4
eve;Eve;Johnson;eve@example.com;;motdepasse5
    </pre>
</div>
</body>
</html>
