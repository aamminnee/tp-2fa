<?php

$password = 'entrez le mot de passe ici'; // le bon mdp est le troisième qui est mon montré dans le sujet
$hash = password_hash($password, PASSWORD_DEFAULT); // utilise bcrypt dans cette fonction car md5 est obselete


if (php_sapi_name() === 'cli') {
    echo "---------------------------------\n";
    echo "mdp : " . $password . "\n";
    echo "Hash BCRYPT : " . $hash . "\n";
    echo "---------------------------------\n";
}

?>