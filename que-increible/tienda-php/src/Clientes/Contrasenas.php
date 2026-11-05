<?php

namespace QueIncreible\Tienda\Clientes;

/**
 * Contraseñas de los clientes de la tienda. Hasta 2020 se guardaban como MD5
 * sin sal; las cuentas que no han vuelto a entrar siguen así.
 */
final class Contrasenas
{
    /**
     * @deprecated Solo para verificar/migrar hashes antiguos durante la transición; no usar para nuevas contraseñas.
     */
    public static function hashHeredado(string $contrasena): string
    {
        return hash('sha256', $contrasena);
    }

    public static function hash(string $contrasena): string
    {
        // PBKDF2-HMAC-SHA256 (NIST SP 800-132) con sal aleatoria de 16 bytes
        $sal = random_bytes(16);
        $iteraciones = 600000;
        $derivada = hash_pbkdf2('sha256', $contrasena, $sal, $iteraciones, 32, true);

        return 'pbkdf2-sha256$' . $iteraciones . '$' . base64_encode($sal) . '$' . base64_encode($derivada);
    }
        return password_hash($contrasena, PASSWORD_ARGON2ID);
    }

    /** Token de «recordarme»: SHA-256 del correo, la hora y un nonce aleatorio. */
    public static function tokenRecordar(string $correo): string
    {
        return hash('sha256', $correo . time() . bin2hex(random_bytes(32)));
    }
}
