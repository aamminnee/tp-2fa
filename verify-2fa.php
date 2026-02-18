<?php
/**
 * verification du code otp et sauvegarde en base de donnes.
 */

session_start();
date_default_timezone_set('Europe/Paris');

require_once __DIR__ . '/TwoFactorAuthLight.php';

if (!isset($_SESSION['user']) || empty($_SESSION['tfa_secret_temp'])) {
    header('Location: login.php');
    exit();
}

// echappe les caracteres speciaux pour un affichage html securise
function h($str) {
    return htmlspecialchars($str ?? '', ENT_QUOTES, 'UTF-8');
}

$tfa = new TwoFactorAuthLight();
$secret = $_SESSION['tfa_secret_temp'];
$userCode = isset($_POST['code']) ? preg_replace('/\D/', '', $_POST['code']) : '';
$userId = $_SESSION['user']['id'];

echo '<!DOCTYPE html><html lang="fr"><head><title>Vérification</title></head><body>';
echo "<h3>🕒 Codes TOTP autour de maintenant</h3>";
echo "<table border='1' cellpadding='5' style='border-collapse: collapse;'>";
echo "<tr><th>Décalage</th><th>TimeSlice</th><th>Début</th><th>Fin</th><th>Code</th><th>Match ?</th></tr>";

$currentTimeSlice = (int) floor(time() / 30);

// genere les codes pour les intervalles adjacents a des fins de demonstration
for ($i = -3; $i <= 3; $i++) {
    $timeSlice = $currentTimeSlice + $i;
    $startTs = $timeSlice * 30;
    $expected = $tfa->getCode($secret, $timeSlice);
    $match = hash_equals($expected, $userCode) ? "✅ Oui" : "❌ Non";
    
    echo "<tr><td>" . h($i) . "</td><td>" . h($timeSlice) . "</td><td>" . h(date('Y-m-d H:i:s', $startTs)) . "</td><td>" . h(date('Y-m-d H:i:s', $startTs + 30)) . "</td><td>" . h($expected) . "</td><td>" . $match . "</td></tr>";
}
echo "</table>";

$isValid = $tfa->verifyCode($secret, $userCode, 1);

if (!$isValid) {
    echo "<h1>❌ Code invalide</h1>";
    exit();
}

$db_file = __DIR__ . '/tp-2fa.db';
$db = new SQLite3($db_file);

$backupCodes = [];
for ($i = 0; $i < 5; $i++) {
    // genere un code de secours aleatoire a 6 chiffres complete par des zeros
    $backupCodes[] = str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
}
$backupCodesStr = implode(',', $backupCodes);

// hache la liste des codes de secours avant le stockage
$hashedBackupCodes = password_hash($backupCodesStr, PASSWORD_DEFAULT);

// met a jour l'utilisateur avec son nouveau secret et ses codes haches
$stmt = $db->prepare("UPDATE users SET secret_2fa = :secret, tfa_backup_codes = :backupCodes, twofa_enabled = 1 WHERE id = :id");
$stmt->bindValue(':secret', $secret, SQLITE3_TEXT);
$stmt->bindValue(':backupCodes', $hashedBackupCodes, SQLITE3_TEXT);
$stmt->bindValue(':id', $userId, SQLITE3_INTEGER);

$res = $stmt->execute();

if (!$res) {
    echo "<h1>❌ Erreur SQL</h1>";
    exit();
}

$_SESSION['user']['tfa_secret'] = $secret;
unset($_SESSION['tfa_secret_temp']);

echo "<h1>✅ 2FA activée avec succès !</h1>";
echo "<pre>" . h($backupCodesStr) . "</pre>";
echo "</body></html>";
?>