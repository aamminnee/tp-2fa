<?php
/**
 * verification des identifiants et initialisation session.
 */

session_start();

// force le passage en https sauf pour le developpement en local
if ($_SERVER['SERVER_NAME'] !== 'localhost' && $_SERVER['SERVER_NAME'] !== '127.0.0.1') {
    if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === "off") {
        $redirect = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
        header('HTTP/1.1 301 Moved Permanently');
        header('Location: ' . $redirect);
        exit();
    }
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    die("Erreur : La méthode doit être POST.");
}

// nettoie les espaces inutiles en debut et fin de saisie
$email = isset($_POST['email']) ? trim((string)$_POST['email']) : '';
$password = isset($_POST['password']) ? trim((string)$_POST['password']) : '';

if (empty($email) || empty($password)) {
    header('Location: login.php?error=generic');
    exit();
}

$db_file = __DIR__ . '/tp-2fa.db';
if (!file_exists($db_file)) {
    die("Erreur : Base de données introuvable.");
}

try {
    $db = new SQLite3($db_file);
    
    // utilise une requete preparee pour eviter les injections sql
    $stmt = $db->prepare('SELECT * FROM users WHERE email = :email');
    $stmt->bindValue(':email', $email, SQLITE3_TEXT);
    
    $result = $stmt->execute();
    $user = $result->fetchArray(SQLITE3_ASSOC);
    
    // compare le mot de passe saisi avec le hash stocke en base
    if ($user && password_verify($password, $user['password'])) {
        
        // change l'identifiant de session pour prevenir la fixation de session
        session_regenerate_id(true);
        
        $_SESSION['user'] = [
            'id' => (int)$user['id'],
            'email' => (string)$user['email'],
            'tfa_secret' => (string)($user['secret_2fa'] ?? '')
        ];
        
        unset($_SESSION['tfa_secret_temp']);
        
        // redirige vers la validation ou la config selon l'etat de la 2fa
        if (!empty($_SESSION['user']['tfa_secret'])) {
            header('Location: check-2fa.php');
        } else {
            header('Location: setup-2fa.php');
        }
        exit();
        
    } else {
        header('Location: login.php?error=credentials');
        exit();
    }

} catch (Throwable $e) {
    header('Location: login.php?error=generic');
    exit();
}
?>