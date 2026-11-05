package queincreible.pagos.firma;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import javax.crypto.KeyAgreement;

import java.security.*;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.Arrays;

/** Clave de sesión con el HSM de la red: híbrido X25519 + ML-KEM-768 (FIPS 203). El DH-2048 heredado debe retirarse. */
public class AcuerdoClaves {

    static {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    private static final byte[] INFO_HIBRIDO = "pagos-hsm/x25519+ml-kem-768/v1".getBytes();

    /** Resultado del lado iniciador: secreto de sesión + encapsulado ML-KEM a enviar al HSM. */
    public record SecretoHibrido(byte[] secreto, byte[] encapsuladoMlKem) {}

    public KeyPair generarParMlKem() throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BCPQC");
        kpg.initialize(MLKEMParameterSpec.ml_kem_768, new SecureRandom());
        return kpg.generateKeyPair();
    }

    public KeyPair generarParX25519() throws GeneralSecurityException {
        return KeyPairGenerator.getInstance("X25519", "BC").generateKeyPair();
    }

    /** Lado iniciador: encapsula contra la clave ML-KEM del HSM y acuerda X25519; combina ambos con HKDF. */
    public SecretoHibrido secretoHibridoIniciador(KeyPair propioX25519, PublicKey ajenaX25519, PublicKey ajenaMlKem)
            throws GeneralSecurityException {
        byte[] secretoClasico = secretoX25519(propioX25519, ajenaX25519);

        KeyGenerator kem = KeyGenerator.getInstance("ML-KEM", "BCPQC");
        kem.init(new KEMGenerateSpec(ajenaMlKem, "AES", 256), new SecureRandom());
        SecretKeyWithEncapsulation enc = (SecretKeyWithEncapsulation) kem.generateKey();

        byte[] secreto = combinar(secretoClasico, enc.getEncoded());
        return new SecretoHibrido(secreto, enc.getEncapsulation());
    }

    /** Lado receptor: desencapsula con la clave privada ML-KEM y acuerda X25519; combina ambos con HKDF. */
    public byte[] secretoHibridoReceptor(KeyPair propioX25519, PublicKey ajenaX25519,
                                         PrivateKey propiaMlKem, byte[] encapsuladoMlKem)
            throws GeneralSecurityException {
        byte[] secretoClasico = secretoX25519(propioX25519, ajenaX25519);

        KeyGenerator kem = KeyGenerator.getInstance("ML-KEM", "BCPQC");
        kem.init(new KEMExtractSpec(propiaMlKem, encapsuladoMlKem, "AES", 256), new SecureRandom());
        SecretKeyWithEncapsulation dec = (SecretKeyWithEncapsulation) kem.generateKey();

        return combinar(secretoClasico, dec.getEncoded());
    }

    private byte[] secretoX25519(KeyPair propio, PublicKey ajena) throws GeneralSecurityException {
        KeyAgreement acuerdo = KeyAgreement.getInstance("X25519", "BC");
        acuerdo.init(propio.getPrivate());
        acuerdo.doPhase(ajena, true);
        return acuerdo.generateSecret();
    }

    /** HKDF-SHA256 sobre la concatenación (X25519 || ML-KEM) para obtener la clave de sesión de 32 bytes. */
    private byte[] combinar(byte[] secretoClasico, byte[] secretoPqc) {
        byte[] ikm = Arrays.concatenate(secretoClasico, secretoPqc);
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(ikm, null, INFO_HIBRIDO));
        byte[] clave = new byte[32];
        hkdf.generateBytes(clave, 0, clave.length);
        Arrays.clear(ikm);
        Arrays.clear(secretoClasico);
        Arrays.clear(secretoPqc);
        return clave;
    }
}

    public KeyPair parDh() throws GeneralSecurityException {
        KeyPairGenerator generador = KeyPairGenerator.getInstance("DH");
        generador.initialize(2048);
        return generador.generateKeyPair();
    }
}
