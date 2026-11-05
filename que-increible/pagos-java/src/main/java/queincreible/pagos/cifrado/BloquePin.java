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

    /**
     * Antes DES simple para terminales de 2009 (retirado: clave de 56 bits y ECB).
     * Ahora AES-256-GCM: el IV aleatorio de 12 bytes se antepone al criptograma (IV || criptograma || tag).
     * Requiere imports: java.security.SecureRandom, javax.crypto.spec.GCMParameterSpec, java.security.InvalidKeyException
     */
    public byte[] cifrarBloqueTerminalAntiguo(byte[] bloquePin, SecretKey claveAes) throws GeneralSecurityException {
        if (claveAes.getEncoded() == null || claveAes.getEncoded().length != 32) {
            throw new InvalidKeyException("Se requiere una clave AES de 256 bits");
        }
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher cifrador = Cipher.getInstance("AES/GCM/NoPadding");
        cifrador.init(Cipher.ENCRYPT_MODE, claveAes, new GCMParameterSpec(128, iv));
        byte[] criptograma = cifrador.doFinal(bloquePin);
        byte[] salida = new byte[iv.length + criptograma.length];
        System.arraycopy(iv, 0, salida, 0, iv.length);
        System.arraycopy(criptograma, 0, salida, iv.length, criptograma.length);
        return salida;
    }
}
