<?php
/**
 * check-2f.php
 * gère la vérification du code 2fa soumis par l'utilisateur
 */

session_start();
require_once 'TwoFactorAuthLight.php';

// vérifie si l'utilisateur est dans l'état de connexion intermédiaire
// cette variable de session doit être définie par verify-2fa.php ou check-login.php avant de rediriger ici
if (!isset($_SESSION['temp_user_id'])) {
    header('Location: login.php');
    exit();
}

$tempUserId = $_SESSION['temp_user_id'];
$userCode = $_POST['code'] ?? '';

// supprime les espaces du code si l'utilisateur en a ajouté
$userCode = str_replace(' ', '', $userCode);

// validation de base
if (empty($userCode)) {
    header('Location: verify-2fa.php?error=empty');
    exit();
}

// connexion à la base de données sqlite
try {
    // en supposant que le fichier db est dans le même répertoire
    $db = new SQLite3('tp-2fa.db');
} catch (Exception $e) {
    die('database connection error');
}

// préparer la requête pour récupérer le secret de l'utilisateur
$stmt = $db->prepare('SELECT id, tfa_secret FROM users WHERE id = :id');
$stmt->bindValue(':id', $tempUserId, SQLITE3_INTEGER);

$result = $stmt->execute();
$user = $result->fetchArray(SQLITE3_ASSOC);

if (!$user) {
    // utilisateur non trouvé, déconnexion forcée
    session_unset();
    session_destroy();
    header('Location: login.php');
    exit();
}

$secret = $user['tfa_secret'];

// initialiser la librairie 2fa
$tfa = new TwoFactorAuthLight();
$isValid = $tfa->verifyCode($secret, $userCode, 1);

if ($isValid) {
    // le code est correct, finaliser la session
    $_SESSION['user_id'] = $user['id'];
    
    // nettoyer les variables de session temporaires
    unset($_SESSION['temp_user_id']);

    // rediriger vers la page principale de l'application
    header('Location: generate_password.php');
    exit();
} else {
    // le code est incorrect, rediriger vers la page de vérification avec une erreur
    header('Location: verify-2fa.php?error=invalid');
    exit();
}
?>