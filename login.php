<?php

session_start();

if (isset($_SESSION['user'])) {
    if (!empty($_SESSION['user']['tfa_secret'])) {
        header('Location: check-2fa.php');
        exit();
    } else {
        header('Location: setup-2fa.php');
        exit();
    }
}

$error_msg = '';
if (isset($_GET['error'])) {
    if ($_GET['error'] === 'expired') {
        $error_msg = "Votre session a expiré. Merci de vous reconnecter.";
    } elseif ($_GET['error'] === 'credentials') {
        $error_msg = "Email ou mot de passe incorrect.";
    } else {
        $error_msg = "Une erreur est survenue.";
    }
}

?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connexion - TP 2FA</title>
</head>
<body>
    <h1>Connexion</h1>

    <?php if ($error_msg): ?>
        <p style="color: red; font-weight: bold;"><?php echo htmlspecialchars($error_msg); ?></p>
    <?php endif; ?>

    <form action="check-login.php" method="POST">
        <div class="form-group">
            <label for="email">Email</label>
            <input type="text" id="email" name="email" required 
                   placeholder="Votre email">
        </div>
        
        <div class="form-group">
            <label for="password">Mot de passe</label>
            <div class="password-wrapper">
                <input type="password" id="password" name="password" required 
                       placeholder="************">
            </div>
        </div>

        <button type="submit" class="btn-submit">Se connecter</button>
    </form>
</body>
</html>