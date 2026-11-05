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

    /** Clave de los pedidos: híbrido X25519 + ML-KEM-768 (FIPS 203). */
    public static function nuevaClave(): array
    {
        // Componente clásica (X25519) con ext-openssl.
        $x25519 = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_X25519]);
        if ($x25519 === false) {
            throw new \RuntimeException('No se pudo generar la clave X25519: ' . openssl_error_string());
        }

        // Componente post-cuántica (ML-KEM-768) con OpenSSL >= 3.5.
        $privPem = self::ejecutarOpenssl(['genpkey', '-algorithm', 'mlkem768']);
        $pubPem  = self::ejecutarOpenssl(['pkey', '-pubout'], $privPem);

        return [
            'x25519'          => $x25519,
            'mlkem768_priv'   => $privPem,
            'mlkem768_pub'    => $pubPem,
        ];
        // Al cifrar un pedido: ss = HKDF(sha256, ss_x25519 || ss_mlkem768) -> clave AES-256-GCM.
    }

    private static function ejecutarOpenssl(array $args, ?string $stdin = null): string
    {
        $cmd = 'openssl ' . implode(' ', array_map('escapeshellarg', $args));
        $proc = proc_open($cmd, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!\is_resource($proc)) {
            throw new \RuntimeException('No se pudo invocar openssl');
        }
        if ($stdin !== null) {
            fwrite($pipes[0], $stdin);
        }
        fclose($pipes[0]);
        $out = stream_get_contents($pipes[1]);
        $err = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        if (proc_close($proc) !== 0) {
            throw new \RuntimeException('Fallo openssl: ' . $err);
        }
        return $out;
    }

    /** Clave de los recibos: HÍBRIDA ECDSA P-256 + ML-DSA-65 (FIPS 204). */
    public static function claveRecibos(): array
    {
        $ec = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);

        // ML-DSA-65 vía OpenSSL 3.5+ (PEM PKCS#8); requiere `openssl` ≥ 3.5 en PATH.
        $pq = tempnam(sys_get_temp_dir(), 'mldsa65_');
        self::ejecutarOpenssl(['genpkey', '-algorithm', 'ML-DSA-65', '-out', $pq]);
        $pqPriv = file_get_contents($pq);
        unlink($pq);

        return ['ec' => $ec, 'mldsa65' => $pqPriv];
    }

    /** Firma híbrida: ECDSA P-256 || ML-DSA-65 (ambas deben verificar). */
    public static function firmarPedido(string $pedido, array $clave): string
    {
        openssl_sign($pedido, $firmaEc, $clave['ec'], OPENSSL_ALGO_SHA256);

        $priv = tempnam(sys_get_temp_dir(), 'mldsa65_');
        $msg  = tempnam(sys_get_temp_dir(), 'pedido_');
        file_put_contents($priv, $clave['mldsa65']);
        file_put_contents($msg, $pedido);
        $firmaPq = self::ejecutarOpenssl(['pkeyutl', '-sign', '-rawin', '-inkey', $priv, '-in', $msg]);
        unlink($priv);
        unlink($msg);

        return json_encode([
            'alg'    => 'ECDSA-P256+ML-DSA-65',
            'ecdsa'  => base64_encode($firmaEc),
            'mldsa'  => base64_encode($firmaPq),
        ]);
    }

    private static function ejecutarOpenssl(array $args): string
    {
        $cmd = 'openssl ' . implode(' ', array_map('escapeshellarg', $args));
        $proc = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        $out = stream_get_contents($pipes[1]);
        $err = stream_get_contents($pipes[2]);
        if (proc_close($proc) !== 0) {
            throw new \RuntimeException('OpenSSL ML-DSA falló: ' . $err);
        }
        return $out;
    }
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

    /** Sobres para el almacén: híbrido X25519 + ML-KEM-768 (FIPS 203) con XChaCha20-Poly1305. */
    public static function sobreAlmacen(string $mensaje, string $publicaAlmacenX25519, string $publicaAlmacenMlkem): string
    {
        // 1) Parte clásica: X25519 efímero contra la clave pública X25519 del almacén
        $efimera = sodium_crypto_box_keypair();
        $efimeraPub = sodium_crypto_box_publickey($efimera);
        $efimeraSec = sodium_crypto_box_secretkey($efimera);
        $ssX25519 = sodium_crypto_scalarmult($efimeraSec, $publicaAlmacenX25519);

        // 2) Parte post-cuántica: encapsulación ML-KEM-768 (liboqs vía FFI)
        $oqs = \FFI::cdef(
            'typedef struct OQS_KEM OQS_KEM;
             OQS_KEM *OQS_KEM_new(const char *method_name);
             int OQS_KEM_encaps(const OQS_KEM *kem, unsigned char *ct, unsigned char *ss, const unsigned char *pk);
             void OQS_KEM_free(OQS_KEM *kem);',
            'liboqs.so'
        );
        $kem = $oqs->OQS_KEM_new('ML-KEM-768');
        $ct = $oqs->new('unsigned char[1088]');  // longitud ciphertext ML-KEM-768
        $ss = $oqs->new('unsigned char[32]');    // secreto compartido ML-KEM-768
        $pk = $oqs->new('unsigned char[1184]');  // clave pública ML-KEM-768
        \FFI::memcpy($pk, $publicaAlmacenMlkem, 1184);
        if ($oqs->OQS_KEM_encaps($kem, $ct, $ss, $pk) !== 0) {
            throw new \RuntimeException('Fallo en encapsulación ML-KEM-768');
        }
        $kemCt = \FFI::string($ct, 1088);
        $ssMlkem = \FFI::string($ss, 32);
        $oqs->OQS_KEM_free($kem);

        // 3) Combinación de secretos vía KDF (HKDF-SHA256) ligando el contexto
        $clave = hash_hkdf('sha256', $ssX25519 . $ssMlkem, 32, 'tienda-php/sobre-almacen/v2', $efimeraPub . $kemCt);

        // 4) Cifrado simétrico autenticado del mensaje
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $cifrado = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($mensaje, $efimeraPub . $kemCt, $nonce, $clave);

        sodium_memzero($efimeraSec);
        sodium_memzero($ssX25519);
        sodium_memzero($ssMlkem);
        sodium_memzero($clave);

        // Sobre: efimeraPub(32) || kemCt(1088) || nonce(24) || cifrado
        return $efimeraPub . $kemCt . $nonce . $cifrado;
    }
}
