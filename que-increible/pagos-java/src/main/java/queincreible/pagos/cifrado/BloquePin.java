package queincreible.pagos.cifrado;

import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * Bloque de PIN (ISO 9564 formato 0) hacia el adquirente. El adquirente aún
 * exige Triple DES con la clave de zona (ZPK): 3DES está roto (SWEET32).
 */
public class BloquePin {

    private static final int LONGITUD_IV_GCM = 12;      // 96 bits recomendado por NIST SP 800-38D
    private static final int LONGITUD_TAG_GCM = 128;    // bits
    private static final SecureRandom ALEATORIO = new SecureRandom();

    public byte[] cifrarBloque(byte[] bloquePin, byte[] zpk) throws GeneralSecurityException {
        if (zpk == null || zpk.length != 32) {
            throw new InvalidKeyException("La ZPK debe ser AES-256 (32 bytes)");
        }
        SecretKey clave = new SecretKeySpec(zpk, "AES");
        byte[] iv = new byte[LONGITUD_IV_GCM];
        ALEATORIO.nextBytes(iv);
        Cipher cifrador = Cipher.getInstance("AES/GCM/NoPadding");
        cifrador.init(Cipher.ENCRYPT_MODE, clave, new GCMParameterSpec(LONGITUD_TAG_GCM, iv));
        byte[] textoCifrado = cifrador.doFinal(bloquePin);
        // Se antepone el IV al resultado: [IV(12)] + [cifrado + tag(16)]
        byte[] salida = new byte[iv.length + textoCifrado.length];
        System.arraycopy(iv, 0, salida, 0, iv.length);
        System.arraycopy(textoCifrado, 0, salida, iv.length, textoCifrado.length);
        return salida;
    }

    /** Terminales de 2009 que solo hablan DES simple: se mantiene por compatibilidad. */
    public byte[] cifrarBloqueTerminalAntiguo(byte[] bloquePin, SecretKey claveDes) throws GeneralSecurityException {
        Cipher cifrador = Cipher.getInstance("DES/ECB/NoPadding");
        cifrador.init(Cipher.ENCRYPT_MODE, claveDes);
        return cifrador.doFinal(bloquePin);
    }
}
