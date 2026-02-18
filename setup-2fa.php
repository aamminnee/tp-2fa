<?php
/**
 * page de configuration de la 2fa avec generation de qr code.
 */

// interdit la mise en cache pour garantir un nouveau secret a chaque essai
ini_set('session.cache_limiter', 'nocache');
session_cache_limiter('nocache');

session_start();
date_default_timezone_set('Europe/Paris');

require_once __DIR__ . '/phpqrcode/qrlib.php';
require_once __DIR__ . '/TwoFactorAuthLight.php';

if (!isset($_SESSION['user'])) {
    header('Location: login.php?error=expired');
    exit();
}

$tfa = new TwoFactorAuthLight();

// genere un secret temporaire uniquement s'il n'existe pas encore en session
if (empty($_SESSION['tfa_secret_temp'])) {
    $_SESSION['tfa_secret_temp'] = $tfa->createSecret();
}

$secret = $_SESSION['tfa_secret_temp'];
$email = $_SESSION['user']['email'];
$issuer = 'TP-2FA';

$label = $issuer . ':' . $email;
$otpauthUrl = $tfa->getQRCodeUrl($label, $secret, $issuer);

$qrFile = __DIR__ . '/qrcode.png';
// ecrit physiquement l'image du qr code sur le disque du serveur
if (is_writable(__DIR__)) {
    QRcode::png($otpauthUrl, $qrFile);
} else {
    die("Erreur : Le dossier n'est pas accessible en écriture pour créer qrcode.png");
}

?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Configuration 2FA</title>
</head>
<body>
    <h2>Configuration de la 2FA</h2>
    <p>Compte : <strong><?php echo htmlspecialchars($email, ENT_QUOTES, 'UTF-8'); ?></strong></p>
    <p>Clé secrète : <code><?php echo htmlspecialchars($secret, ENT_QUOTES, 'UTF-8'); ?></code></p>
    <p>Valide (A-Z2-7) : <?php // verifie si le secret respecte bien l'alphabet base32
    echo (preg_match('/^[A-Z2-7]+$/', $secret) ? '✅ Oui' : '❌ Non'); ?></p>

    <h3>📱 Scanne le QR code</h3>
    <img src="qrcode.png?v=<?php echo time(); ?>" alt="QR Code 2FA"><br><br>

    <h3>🔐 Validation</h3>
    <form method="POST" action="verify-2fa.php" autocomplete="off">
        <label for="code">Code à 6 chiffres :</label><br>
        <input type="text" name="code" id="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required autofocus><br><br>
        <button type="submit">Valider la 2FA</button>
    </form>
</body>
</html>