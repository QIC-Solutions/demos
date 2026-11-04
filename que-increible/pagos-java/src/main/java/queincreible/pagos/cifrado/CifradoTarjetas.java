package queincreible.pagos.cifrado;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Cifrado del PAN (número de tarjeta) antes de guardarlo en la base de cobros.
 *
 * DEMO: la primera versión usa AES en modo ECB con una clave de 128 bits
 * escrita en el código. Está así A PROPÓSITO para que |QS>EDR lo detecte.
 */
public class CifradoTarjetas {

    // Clave de 128 bits fija (ficticia): antiagilidad y criptografía incrustada.
    private static final byte[] CLAVE_PAN = "QIC-demo-128bits".getBytes(StandardCharsets.US_ASCII);

    /** Versión heredada: AES-128 en ECB, el mismo PAN siempre da el mismo cifrado. */
    public byte[] cifrarPanHeredado(String pan) throws GeneralSecurityException {
        Cipher cifrador = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cifrador.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(CLAVE_PAN, "AES"));
        return cifrador.doFinal(pan.getBytes(StandardCharsets.US_ASCII));
    }

    /** Versión nueva: AES-256-GCM con IV aleatorio. Algoritmo y tamaño, aún fijos. */
    public byte[] cifrarPan(String pan) throws GeneralSecurityException {
        KeyGenerator generador = KeyGenerator.getInstance("AES");
        generador.init(256);
        SecretKey clave = generador.generateKey();
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher cifrador = Cipher.getInstance("AES/GCM/NoPadding");
        cifrador.init(Cipher.ENCRYPT_MODE, clave, new GCMParameterSpec(128, iv));
        return cifrador.doFinal(pan.getBytes(StandardCharsets.US_ASCII));
    }
}
