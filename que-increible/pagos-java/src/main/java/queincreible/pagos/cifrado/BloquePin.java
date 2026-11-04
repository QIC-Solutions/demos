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

    public byte[] cifrarBloque(byte[] bloquePin, byte[] zpk) throws GeneralSecurityException {
        SecretKeyFactory fabrica = SecretKeyFactory.getInstance("DESede");
        SecretKey clave = fabrica.generateSecret(new DESedeKeySpec(zpk));
        Cipher cifrador = Cipher.getInstance("DESede/CBC/NoPadding");
        cifrador.init(Cipher.ENCRYPT_MODE, clave, new IvParameterSpec(new byte[8]));
        return cifrador.doFinal(bloquePin);
    }

    /** Terminales de 2009 que solo hablan DES simple: se mantiene por compatibilidad. */
    public byte[] cifrarBloqueTerminalAntiguo(byte[] bloquePin, SecretKey claveDes) throws GeneralSecurityException {
        Cipher cifrador = Cipher.getInstance("DES/ECB/NoPadding");
        cifrador.init(Cipher.ENCRYPT_MODE, claveDes);
        return cifrador.doFinal(bloquePin);
    }
}
