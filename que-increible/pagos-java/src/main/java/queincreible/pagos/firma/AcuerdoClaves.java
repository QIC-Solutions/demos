package queincreible.pagos.firma;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import javax.crypto.KeyAgreement;

/** Clave de sesión con el HSM de la red: ECDH clásico y un DH-2048 heredado. */
public class AcuerdoClaves {

    public byte[] secretoEcdh(KeyPair propio, PublicKey ajena) throws GeneralSecurityException {
        KeyAgreement acuerdo = KeyAgreement.getInstance("ECDH");
        acuerdo.init(propio.getPrivate());
        acuerdo.doPhase(ajena, true);
        return acuerdo.generateSecret();
    }

    public KeyPair parDh() throws GeneralSecurityException {
        KeyPairGenerator generador = KeyPairGenerator.getInstance("DH");
        generador.initialize(2048);
        return generador.generateKeyPair();
    }
}
