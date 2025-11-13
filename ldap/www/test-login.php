<!DOCTYPE html>
<html>
<head>
    <title>Test Keycloak Login</title>
    <style>
        body { font-family: Arial; max-width: 600px; margin: 50px auto; padding: 20px; }
        .btn { padding: 15px 30px; background: #0066cc; color: white; text-decoration: none; border-radius: 5px; display: inline-block; margin: 10px; }
        .info { background: #f0f0f0; padding: 15px; border-radius: 5px; margin: 20px 0; }
        h1 { color: #333; }
    </style>
</head>
<body>
    <h1>Test Keycloak Authentication</h1>

    <div class="info">
        <h3>Utilisateurs LDAP disponibles:</h3>
        <ul>
            <li><strong>bob</strong> / leponge</li>
            <li><strong>alice</strong> / lapin</li>
            <li><strong>testuser</strong> / testpass</li>
        </ul>
    </div>

    <?php
    session_start();

    if (isset($_GET['logout'])) {
        session_destroy();
        header('Location: test-login.php');
        exit;
    }

    if (isset($_SESSION['user'])) {
        echo "<div class='info'>";
        echo "<h2>✅ Connecté en tant que: " . htmlspecialchars($_SESSION['user']) . "</h2>";
        echo "<p>Bienvenue ! Vous êtes authentifié via Keycloak.</p>";
        echo "<a href='?logout=1' class='btn'>Se déconnecter</a>";
        echo "</div>";
    } else {
        echo "<p>Cliquez sur le bouton ci-dessous pour vous connecter via Keycloak :</p>";
        echo "<a href='keycloak-login.php' class='btn'>🔐 Se connecter avec Keycloak</a>";
    }
    ?>

</body>
</html>
