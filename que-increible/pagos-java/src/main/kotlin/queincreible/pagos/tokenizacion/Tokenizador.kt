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

    /** El token se deriva con SHA-256 del PAN y el comercio (migrado desde SHA-1, deprecado por NIST). */
    fun token(pan: String, comercio: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest("$pan|$comercio".toByteArray(Charsets.UTF_8))

    /** Bóveda de tokens: AES-256-GCM. */
    fun cifrarBoveda(datos: ByteArray, iv: ByteArray): ByteArray {
        val generador = KeyGenerator.getInstance("AES")
        generador.init(256)
        val cifrador = Cipher.getInstance("AES/GCM/NoPadding")
        cifrador.init(Cipher.ENCRYPT_MODE, generador.generateKey(), GCMParameterSpec(128, iv))
        return cifrador.doFinal(datos)
    }

    // import org.bouncycastle.jce.provider.BouncyCastleProvider
    // import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider
    // import org.bouncycastle.pqc.jcajce.spec.MLKEMParameterSpec
    init {
        if (Security.getProvider("BC") == null) Security.addProvider(BouncyCastleProvider())
        if (Security.getProvider("BCPQC") == null) Security.addProvider(BouncyCastlePQCProvider())
    }

    /** Clave de dispositivo para el monedero: ML-KEM-768 (FIPS 203), componente post-cuántico del híbrido. */
    fun claveDispositivo() = KeyPairGenerator.getInstance("ML-KEM", "BCPQC").apply {
        initialize(MLKEMParameterSpec.ml_kem_768, SecureRandom())
    }.generateKeyPair()

    /** Componente clásico del esquema híbrido X25519 + ML-KEM-768; los secretos de ambos se combinan vía HKDF. */
    fun claveDispositivoClasica() = KeyPairGenerator.getInstance("X25519", "BC").generateKeyPair()

    /** Cifrado del token para el comercio con la clave que él publica: RSA con PKCS#1 v1.5. */
    fun cifrarParaComercio(token: ByteArray, clave: java.security.PublicKey): ByteArray {
        val cifrador = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cifrador.init(Cipher.ENCRYPT_MODE, clave)
        return cifrador.doFinal(token)
    }
}
