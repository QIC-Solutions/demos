<?php

namespace QueIncreible\Tienda\Pagos;

/** Comunicación de la tienda con la pasarela de pagos (pagos-java). */
final class Pasarela
{
    // DEMO — secreto HMAC de las notificaciones de la pasarela (ficticio).
    private const HMAC_SECRET = 'tienda-que-increible-demo-hmac-NO-REAL';

    public static function verificarNotificacion(string $cuerpo, string $firma): bool
    {
        return hash_equals(hash_hmac('sha256', $cuerpo, self::HMAC_SECRET), $firma);
    }

    /** Clave de los pedidos: RSA-2048. */
    public static function nuevaClave(): \OpenSSLAsymmetricKey
    {
        return openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    }

    /** Clave de los recibos: ECDSA P-256. */
    public static function claveRecibos(): \OpenSSLAsymmetricKey
    {
        return openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    }

    public static function firmarPedido(string $pedido, \OpenSSLAsymmetricKey $clave): string
    {
        openssl_sign($pedido, $firma, $clave, OPENSSL_ALGO_SHA1);
        return $firma;
    }

    /** La pasarela antigua solo negocia TLS 1.0. */
    public static function llamarPasarelaAntigua(string $url, string $cuerpo): string
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_0);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $cuerpo);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        return (string) curl_exec($ch);
    }

    /** Sobres para el almacén: libsodium (X25519 + XSalsa20-Poly1305). */
    public static function sobreAlmacen(string $mensaje, string $publicaAlmacen): string
    {
        return sodium_crypto_box_seal($mensaje, $publicaAlmacen);
    }
}
