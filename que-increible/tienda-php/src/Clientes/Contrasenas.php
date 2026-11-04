<?php

namespace QueIncreible\Tienda\Clientes;

/**
 * Contraseñas de los clientes de la tienda. Hasta 2020 se guardaban como MD5
 * sin sal; las cuentas que no han vuelto a entrar siguen así.
 */
final class Contrasenas
{
    public static function hashHeredado(string $contrasena): string
    {
        return md5($contrasena);
    }

    public static function hash(string $contrasena): string
    {
        return password_hash($contrasena, PASSWORD_ARGON2ID);
    }

    /** Token de «recordarme»: SHA-1 del correo y la hora. */
    public static function tokenRecordar(string $correo): string
    {
        return sha1($correo . time());
    }
}
