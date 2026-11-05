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

    private static final int LONGITUD_IV = 12;   // 96 bits recomendados para GCM
    private static final int BITS_TAG = 128;
    private static final SecureRandom ALEATORIO = new SecureRandom();

    public byte[] cifrarBloque(byte[] bloquePin, byte[] zpk) throws GeneralSecurityException {
        if (zpk == null || zpk.length != 32) {
            throw new InvalidKeyException("La ZPK debe ser una clave AES-256 (32 bytes)");
        }
        SecretKey clave = new SecretKeySpec(zpk, "AES");
        byte[] iv = new byte[LONGITUD_IV];
        ALEATORIO.nextBytes(iv);                    // IV único por operación, nunca fijo
        Cipher cifrador = Cipher.getInstance("AES/GCM/NoPadding");
        cifrador.init(Cipher.ENCRYPT_MODE, clave, new GCMParameterSpec(BITS_TAG, iv));
        byte[] cifrado = cifrador.doFinal(bloquePin);  // incluye el tag de autenticación
        // Se antepone el IV al resultado para que el receptor pueda descifrar
        byte[] salida = new byte[iv.length + cifrado.length];
        System.arraycopy(iv, 0, salida, 0, iv.length);
        System.arraycopy(cifrado, 0, salida, iv.length, cifrado.length);
        return salida;
    }
    }

    /** Terminales de 2009 que solo hablan DES simple: se mantiene por compatibilidad. */
    public byte[] cifrarBloqueTerminalAntiguo(byte[] bloquePin, SecretKey claveDes) throws GeneralSecurityException {
        Cipher cifrador = Cipher.getInstance("DES/ECB/NoPadding");
        cifrador.init(Cipher.ENCRYPT_MODE, claveDes);
        return cifrador.doFinal(bloquePin);
    }
}
