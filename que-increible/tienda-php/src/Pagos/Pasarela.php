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

    /** Sobres para el almacén: híbrido PQC (ML-KEM-768 + X25519) + XChaCha20-Poly1305. */
    public static function sobreAlmacen(string $mensaje, string $publicaAlmacenX25519, string $publicaAlmacenMlKem): string
    {
        // 1) Encapsulación post-cuántica ML-KEM-768 (FIPS 203) vía liboqs
        $oqs = \FFI::cdef(
            'typedef struct OQS_KEM OQS_KEM;'
            . 'OQS_KEM *OQS_KEM_new(const char *method_name);'
            . 'int OQS_KEM_encaps(const OQS_KEM *kem, uint8_t *ct, uint8_t *ss, const uint8_t *pk);'
            . 'void OQS_KEM_free(OQS_KEM *kem);',
            'liboqs.so'
        );
        $kem = $oqs->OQS_KEM_new('ML-KEM-768');
        $ct  = \FFI::new('uint8_t[1088]');
        $ssPq = \FFI::new('uint8_t[32]');
        $pk  = \FFI::new('uint8_t[1184]');
        \FFI::memcpy($pk, $publicaAlmacenMlKem, 1184);
        if ($oqs->OQS_KEM_encaps($kem, $ct, $ssPq, $pk) !== 0) {
            $oqs->OQS_KEM_free($kem);
            throw new \RuntimeException('Fallo en ML-KEM-768 encaps');
        }
        $oqs->OQS_KEM_free($kem);
        $kemCt = \FFI::string($ct, 1088);
        $ssPqStr = \FFI::string($ssPq, 32);

        // 2) Componente clásico X25519 efímero (híbrido durante la migración)
        $efimera = sodium_crypto_box_keypair();
        $efimeraPub = sodium_crypto_box_publickey($efimera);
        $ssClasico = sodium_crypto_scalarmult(sodium_crypto_box_secretkey($efimera), $publicaAlmacenX25519);

        // 3) Combinación de ambos secretos -> clave simétrica (KDF)
        $clave = sodium_crypto_generichash(
            $ssPqStr . $ssClasico . $kemCt . $efimeraPub . $publicaAlmacenX25519 . $publicaAlmacenMlKem,
            'tienda-sobre-almacen-v2',
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES
        );

        // 4) Cifrado autenticado del mensaje
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $cifrado = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($mensaje, $kemCt . $efimeraPub, $nonce, $clave);

        sodium_memzero($ssPqStr);
        sodium_memzero($ssClasico);
        sodium_memzero($clave);
        sodium_memzero($efimera);

        // Formato del sobre: ct_mlkem(1088) || pub_x25519_efimera(32) || nonce(24) || cifrado
        return $kemCt . $efimeraPub . $nonce . $cifrado;
    }
}
