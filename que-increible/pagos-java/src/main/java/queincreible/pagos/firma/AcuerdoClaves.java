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
        // 'acuerdo' debe ser KeyAgreement.getInstance("X25519", "BC") en lugar de "DH"
        return acuerdo.generateSecret();
    }

    // Componente clásico del esquema híbrido
    public KeyPair parX25519() throws GeneralSecurityException {
        KeyPairGenerator generador = KeyPairGenerator.getInstance("X25519", "BC");
        return generador.generateKeyPair();
    }

    // Componente post-cuántico: ML-KEM-768 (FIPS 203)
    public KeyPair parMlKem() throws GeneralSecurityException {
        KeyPairGenerator generador = KeyPairGenerator.getInstance("ML-KEM", "BCPQC");
        generador.initialize(MLKEMParameterSpec.ml_kem_768, new SecureRandom());
        return generador.generateKeyPair();
    }

    // Emisor: encapsula contra la clave pública ML-KEM del receptor
    public SecretKeyWithEncapsulation encapsular(PublicKey pubMlKem) throws GeneralSecurityException {
        KeyGenerator kem = KeyGenerator.getInstance("ML-KEM", "BCPQC");
        kem.init(new KEMGenerateSpec(pubMlKem, "AES"), new SecureRandom());
        return (SecretKeyWithEncapsulation) kem.generateKey();
    }

    // Receptor: desencapsula con su clave privada ML-KEM
    public SecretKey desencapsular(PrivateKey privMlKem, byte[] encapsulado) throws GeneralSecurityException {
        KeyGenerator kem = KeyGenerator.getInstance("ML-KEM", "BCPQC");
        kem.init(new KEMExtractSpec(privMlKem, encapsulado, "AES"), new SecureRandom());
        return kem.generateKey();
    }

    // Combinación híbrida: HKDF-SHA256(ss_X25519 || ss_ML-KEM)
    public byte[] secretoHibrido(byte[] ssX25519, byte[] ssMlKem) {
        byte[] ikm = Arrays.concatenate(ssX25519, ssMlKem);
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(ikm, null, "pagos-x25519-mlkem768".getBytes(StandardCharsets.UTF_8)));
        byte[] clave = new byte[32];
        hkdf.generateBytes(clave, 0, 32);
        return clave;
    }
}
