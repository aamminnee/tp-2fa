<?php
/**
 * implementation legere de totp pour la 2fa.
 * base sur la rfc 6238.
 */

class TwoFactorAuthLight
{
    /**
     * genere une cle secrete aleatoire en base32.
     * @param int $length longueur du secret.
     * @return string le secret genere.
     */
    public function createSecret(int $length = 16): string
    {
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $secret = '';
        
        for ($i = 0; $i < $length; $i++) {
            // selectionne un caractere aleatoire securise dans l'alphabet base32
            $secret .= $chars[random_int(0, strlen($chars) - 1)];
        }
        
        return $secret;
    }

    /**
     * genere l'url pour le code qr.
     * @param string $label etiquette du compte.
     * @param string $secret la cle secrete.
     * @param string $issuer le nom de l'application.
     * @return string l'url otpauth.
     */
    public function getQRCodeUrl(string $label, string $secret, string $issuer = 'TP-2FA'): string
    {
        return 'otpauth://totp/' . rawurlencode($label)
             . '?secret=' . rawurlencode($secret)
             . '&issuer=' . rawurlencode($issuer)
             . '&algorithm=SHA1&digits=6&period=30';
    }

    /**
     * calcule le code pour une fenetre de temps donnee.
     * @param string $secret la cle secrete.
     * @param int|null $timeSlice intervalle de temps specifique.
     * @return string le code a 6 chiffres.
     */
    public function getCode(string $secret, ?int $timeSlice = null): string
    {
        if ($timeSlice === null) {
            // calcule l'intervalle actuel par tranches de 30 secondes
            $timeSlice = (int) floor(time() / 30);
        }

        $key = $this->base32Decode($secret);
        
        if ($key === '') {
            return '000000';
        }

        // convertit l'intervalle de temps en binaire sur 8 octets
        $time = pack('N', 0) . pack('N', $timeSlice);
        
        // genere une empreinte hmac-sha1 en utilisant la cle binaire
        $hm = hash_hmac('sha1', $time, $key, true);
        
        // determine la position de depart pour la troncature dynamique
        $offset = ord(substr($hm, -1)) & 0x0F;
        $part = substr($hm, $offset, 4);
        
        // extrait un entier de 31 bits a partir des octets selectionnes
        $value = unpack('N', $part)[1] & 0x7FFFFFFF;
        
        // applique un modulo pour obtenir 6 chiffres avec des zeros a gauche
        return str_pad((string)($value % 1000000), 6, '0', STR_PAD_LEFT);
    }

    /**
     * verifie un code fourni par l'utilisateur.
     * @param string $secret le secret stocke.
     * @param string $code le code saisi.
     * @param int $window marge d'erreur temporelle.
     * @return bool vrai si valide.
     */
    public function verifyCode(string $secret, string $code, int $window = 1): bool
    {
        $code = preg_replace('/\D/', '', $code ?? '');
        
        if (strlen($code) !== 6) {
            return false;
        }

        $current = (int) floor(time() / 30);

        // boucle sur la fenetre de tolerance pour gerer la desynchronisation
        for ($i = -$window; $i <= $window; $i++) {
            // compare les hashs de maniere securisee contre les attaques temporelles
            if (hash_equals($this->getCode($secret, $current + $i), $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * decode une chaine base32 en binaire.
     * @param string $secret secret en base32.
     * @return string chaine binaire resultante.
     */
    private function base32Decode(string $secret): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $secret = strtoupper(trim($secret));
        $secret = preg_replace('/[^A-Z2-7]/', '', $secret);
        
        if ($secret === '') {
            return '';
        }

        $bits = '';
        $len = strlen($secret);
        
        for ($i = 0; $i < $len; $i++) {
            $val = strpos($alphabet, $secret[$i]);
            if ($val === false) {
                continue;
            }
            // convertit chaque caractere en sa valeur binaire sur 5 bits
            $bits .= str_pad(decbin($val), 5, '0', STR_PAD_LEFT);
        }

        $binary = '';
        $bitsLen = strlen($bits);
        
        for ($i = 0; $i + 8 <= $bitsLen; $i += 8) {
            // regroupe les bits par 8 pour former des octets
            $binary .= chr(bindec(substr($bits, $i, 8)));
        }
        
        return $binary;
    }
}
?>