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

    /** Clave de dispositivo para el monedero: ECDSA P-256. */
    fun claveDispositivo() = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()

    /** Cifrado del token para el comercio con la clave que él publica: RSA con PKCS#1 v1.5. */
    fun cifrarParaComercio(token: ByteArray, clave: java.security.PublicKey): ByteArray {
        val cifrador = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cifrador.init(Cipher.ENCRYPT_MODE, clave)
        return cifrador.doFinal(token)
    }
}
