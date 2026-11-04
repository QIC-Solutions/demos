<?php

namespace QueIncreible\Tienda\Clientes;

/** Carritos guardados de los clientes que no terminan la compra. */
final class Carrito
{
    // DEMO — clave de cifrado escrita en el código (ficticia).
    private const ENCRYPTION_KEY = 'VGllbmRhUXVlSW5jcmVpYmxlRGVtbzEyMzQ=';

    /** Versión de 2016: DES-EDE3 en CBC. */
    public static function cifrarHeredado(string $carrito): string
    {
        $iv = random_bytes(8);
        return $iv . openssl_encrypt($carrito, 'des-ede3-cbc', base64_decode(self::ENCRYPTION_KEY), OPENSSL_RAW_DATA, $iv);
    }

    /** Cupones: RC4 (sí, todavía). */
    public static function cifrarCupon(string $cupon): string
    {
        return openssl_encrypt($cupon, 'rc4', base64_decode(self::ENCRYPTION_KEY));
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
