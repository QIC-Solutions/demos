<?php

namespace QueIncreible\Tienda\Clientes;

/** Carritos guardados de los clientes que no terminan la compra. */
final class Carrito
{
    // DEMO — clave de cifrado escrita en el código (ficticia).
    private const ENCRYPTION_KEY = 'VGllbmRhUXVlSW5jcmVpYmxlRGVtbzEyMzQ=';

    /** Versión 2025: AES-256-GCM (AEAD) con nonce de 96 bits y tag de 128 bits. */
    public static function cifrarHeredado(string $carrito): string
    {
        $key = base64_decode(self::ENCRYPTION_KEY, true);
        if ($key === false || strlen($key) !== 32) {
            throw new \RuntimeException('ENCRYPTION_KEY debe ser una clave AES-256 (32 bytes) en base64.');
        }
        $iv  = random_bytes(12); // nonce GCM recomendado por NIST SP 800-38D
        $tag = '';
        $cifrado = openssl_encrypt($carrito, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
        if ($cifrado === false) {
            throw new \RuntimeException('Error al cifrar el carrito: ' . openssl_error_string());
        }
        return $iv . $tag . $cifrado;
    }

    /** Cupones: AES-256-GCM (clave de 256 bits, IV aleatorio de 96 bits, tag de 128 bits). */
    public static function cifrarCupon(string $cupon): string
    {
        $clave = base64_decode(self::ENCRYPTION_KEY); // 32 bytes (256 bits)
        $iv    = random_bytes(12);                     // nunca reutilizar con la misma clave
        $tag   = '';
        $cifrado = openssl_encrypt($cupon, 'aes-256-gcm', $clave, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
        if ($cifrado === false) {
            throw new \RuntimeException('Error al cifrar el cupón');
        }
        // Formato: base64(iv || tag || ciphertext)
        return base64_encode($iv . $tag . $cifrado);
    }

    /** Versión nueva: el algoritmo lo dice config/tienda.php. */
    public static function cifrar(string $carrito, array $config, string $clave): string
    {
        $iv = random_bytes(12);
        $etiqueta = '';
        $cifrado = openssl_encrypt($carrito, $config['cifrado_carrito'], $clave, OPENSSL_RAW_DATA, $iv, $etiqueta);
        return $iv . $etiqueta . $cifrado;
    }

    /** Copias de seguridad del carrito: AES-128-ECB. */
    public static function copia(string $carrito, string $clave): string
    {
        return openssl_encrypt($carrito, 'aes-128-ecb', $clave);
    }
}
