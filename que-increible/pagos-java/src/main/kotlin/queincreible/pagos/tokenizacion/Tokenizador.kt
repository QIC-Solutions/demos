package queincreible.pagos.tokenizacion

import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

/**
 * Módulo Kotlin de la pasarela: tokenización de tarjetas para los pagos
 * recurrentes (el token sustituye al PAN en los sistemas de los comercios).
 */
class Tokenizador {

    /** El token se deriva con SHA-1 del PAN y el comercio (heredado de 2016). */
    fun token(pan: String, comercio: String): ByteArray =
        MessageDigest.getInstance("SHA-1").digest("$pan|$comercio".toByteArray())

    /** Bóveda de tokens: AES-256-GCM. */
    fun cifrarBoveda(datos: ByteArray, iv: ByteArray): ByteArray {
        val generador = KeyGenerator.getInstance("AES")
        generador.init(256)
        val cifrador = Cipher.getInstance("AES/GCM/NoPadding")
        cifrador.init(Cipher.ENCRYPT_MODE, generador.generateKey(), GCMParameterSpec(128, iv))
        return cifrador.doFinal(datos)
    }

    /** Clave de dispositivo para el monedero: híbrido X25519 + ML-KEM-768 (FIPS 203). */
    data class ClaveDispositivoHibrida(val x25519: KeyPair, val mlKem: KeyPair)

    fun claveDispositivo(): ClaveDispositivoHibrida {
        if (Security.getProvider("BCPQC") == null) Security.addProvider(BouncyCastlePQCProvider())
        if (Security.getProvider("BC") == null) Security.addProvider(BouncyCastleProvider())

        val x25519 = KeyPairGenerator.getInstance("X25519", "BC").generateKeyPair()
        val mlKem = KeyPairGenerator.getInstance("ML-KEM", "BCPQC").apply {
            initialize(MLKEMParameterSpec.ml_kem_768, SecureRandom())
        }.generateKeyPair()
        return ClaveDispositivoHibrida(x25519, mlKem)
    }

    /** Encapsula un secreto para el dispositivo: ss = HKDF(ss_X25519 || ss_MLKEM). */
    fun encapsularParaDispositivo(pubX25519: PublicKey, pubMlKem: PublicKey): Pair<ByteArray, SecretKey> {
        // Parte clásica: X25519 efímero
        val efimero = KeyPairGenerator.getInstance("X25519", "BC").generateKeyPair()
        val ssEc = KeyAgreement.getInstance("X25519", "BC").apply {
            init(efimero.private)
            doPhase(pubX25519, true)
        }.generateSecret()

        // Parte post-cuántica: ML-KEM-768
        val kem = KeyGenerator.getInstance("ML-KEM", "BCPQC").apply {
            init(KEMGenerateSpec(pubMlKem, "AES"), SecureRandom())
        }
        val encap = kem.generateKey() as SecretKeyWithEncapsulation

        // Combinación de secretos vía HKDF-SHA256
        val hkdf = HKDFBytesGenerator(SHA256Digest()).apply {
            init(HKDFParameters(ssEc + encap.encoded, null, "monedero-hibrido-v1".toByteArray()))
        }
        val claveFinal = ByteArray(32).also { hkdf.generateBytes(it, 0, it.size) }

        val ctHibrido = efimero.public.encoded + encap.encapsulation
        return ctHibrido to SecretKeySpec(claveFinal, "AES")
    }

    /** Cifrado del token para el comercio con la clave que él publica: RSA con PKCS#1 v1.5. */
    fun cifrarParaComercio(token: ByteArray, clave: java.security.PublicKey): ByteArray {
        val cifrador = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cifrador.init(Cipher.ENCRYPT_MODE, clave)
        return cifrador.doFinal(token)
    }
}
