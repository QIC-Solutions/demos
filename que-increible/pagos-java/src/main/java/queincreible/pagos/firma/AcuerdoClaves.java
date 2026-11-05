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
        import java.security.*;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;

    // Lado emisor: encapsula un secreto con la clave publica ML-KEM-768 del receptor.
    // Devuelve el secreto compartido y el encapsulado (ciphertext) a enviar.
    public SecretKeyWithEncapsulation encapsular(PublicKey publicaMlKem) throws GeneralSecurityException {
        KeyGenerator kem = KeyGenerator.getInstance("ML-KEM", "BCPQC");
        kem.init(new KEMGenerateSpec(publicaMlKem, "AES"), new SecureRandom());
        return (SecretKeyWithEncapsulation) kem.generateKey();
    }

    // Lado receptor: desencapsula el secreto con su clave privada ML-KEM-768.
    public byte[] desencapsular(PrivateKey privadaMlKem, byte[] encapsulado) throws GeneralSecurityException {
        KeyGenerator kem = KeyGenerator.getInstance("ML-KEM", "BCPQC");
        kem.init(new KEMExtractSpec(privadaMlKem, encapsulado, "AES"), new SecureRandom());
        SecretKey secreto = kem.generateKey();
        return secreto.getEncoded();
    }

    // Hibrido: combina el secreto X25519 y el secreto ML-KEM-768 via HKDF-SHA256.
    public byte[] secretoHibrido(byte[] secretoX25519, byte[] secretoMlKem) {
        byte[] ikm = new byte[secretoX25519.length + secretoMlKem.length];
        System.arraycopy(secretoX25519, 0, ikm, 0, secretoX25519.length);
        System.arraycopy(secretoMlKem, 0, ikm, secretoX25519.length, secretoMlKem.length);
        org.bouncycastle.crypto.generators.HKDFBytesGenerator hkdf =
                new org.bouncycastle.crypto.generators.HKDFBytesGenerator(new org.bouncycastle.crypto.digests.SHA256Digest());
        hkdf.init(new org.bouncycastle.crypto.params.HKDFParameters(ikm, null, "pagos-x25519-mlkem768".getBytes()));
        byte[] clave = new byte[32];
        hkdf.generateBytes(clave, 0, 32);
        return clave;
    }

    public KeyPair parMlKem() throws GeneralSecurityException {
        KeyPairGenerator generador = KeyPairGenerator.getInstance("ML-KEM", "BCPQC");
        generador.initialize(MLKEMParameterSpec.ml_kem_768, new SecureRandom());
        return generador.generateKeyPair();
    }

    public KeyPair parX25519() throws GeneralSecurityException {
        KeyPairGenerator generador = KeyPairGenerator.getInstance("X25519");
        return generador.generateKeyPair();
    }
}
