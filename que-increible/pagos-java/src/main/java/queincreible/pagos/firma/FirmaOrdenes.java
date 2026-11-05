package queincreible.pagos.firma;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

/**
 * Firma de las órdenes de cobro que se envían a la red de tarjetas.
 *
 * DEMO: algoritmo y tamaño de clave escritos en la propia llamada. Para pasar a
 * ML-DSA hay que tocar y recompilar cada método (antiagilidad).
 */
import java.security.*;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

public class FirmaOrdenes {

    static {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    /** Material híbrido post-cuántico: X25519 + ML-KEM-768 (FIPS 203). */
    public record ParOrdenesHibrido(KeyPair mlKem, KeyPair x25519) {}

    /** Par híbrido X25519 + ML-KEM-768 para las órdenes: resistente ante un ordenador cuántico. */
    public ParOrdenesHibrido generarParOrdenes() throws GeneralSecurityException {
        KeyPairGenerator generadorPqc = KeyPairGenerator.getInstance("ML-KEM", "BCPQC");
        generadorPqc.initialize(MLKEMParameterSpec.ml_kem_768, new SecureRandom());
        KeyPair parMlKem = generadorPqc.generateKeyPair();

        KeyPairGenerator generadorClasico = KeyPairGenerator.getInstance("X25519", "BC");
        KeyPair parX25519 = generadorClasico.generateKeyPair();

        return new ParOrdenesHibrido(parMlKem, parX25519);
    }

    /** Encapsula un secreto con la clave pública ML-KEM-768 del receptor (lado emisor). */
    public javax.crypto.SecretKeyWithEncapsulation encapsular(PublicKey publicaMlKem) throws GeneralSecurityException {
        KeyGenerator kemGen = KeyGenerator.getInstance("ML-KEM", "BCPQC");
        kemGen.init(new KEMGenerateSpec(publicaMlKem, "AES", 256), new SecureRandom());
        return (javax.crypto.SecretKeyWithEncapsulation) kemGen.generateKey();
    }

    /** Recupera el secreto a partir del encapsulado recibido (lado receptor). */
    public SecretKey desencapsular(PrivateKey privadaMlKem, byte[] encapsulado) throws GeneralSecurityException {
        KeyGenerator kemGen = KeyGenerator.getInstance("ML-KEM", "BCPQC");
        kemGen.init(new KEMExtractSpec(privadaMlKem, encapsulado, "AES", 256));
        return kemGen.generateKey();
    }

    // El secreto ML-KEM y el secreto X25519 (KeyAgreement "X25519", "BC") deben combinarse
    // con HKDF-SHA256 (p. ej. HKDFBytesGenerator de Bouncy Castle) para derivar la clave AES final.
}

    // Requiere: import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
    //           import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
    //           import org.bouncycastle.jce.provider.BouncyCastleProvider;
    //           import java.security.Security;
    static {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    /** Par ML-KEM-768 (FIPS 203) del canal con el banco adquirente: componente post-cuántico del esquema híbrido. */
    public KeyPair generarParAdquirente() throws GeneralSecurityException {
        KeyPairGenerator generadorAdquirente = KeyPairGenerator.getInstance("ML-KEM", "BCPQC");
        generadorAdquirente.initialize(MLKEMParameterSpec.ml_kem_768, new SecureRandom());
        return generadorAdquirente.generateKeyPair();
    }

    /** Par X25519 del canal con el banco adquirente: componente clásico del esquema híbrido (X25519 + ML-KEM-768). */
    public KeyPair generarParAdquirenteClasico() throws GeneralSecurityException {
        KeyPairGenerator generadorClasico = KeyPairGenerator.getInstance("X25519", "BC");
        generadorClasico.initialize(255, new SecureRandom());
        return generadorClasico.generateKeyPair();
    }

    // Encapsulación/decapsulación: usar KeyGenerator.getInstance("ML-KEM", "BCPQC") con
    // KEMGenerateSpec (emisor) / KEMExtractSpec (receptor) y combinar el secreto ML-KEM con el
    // secreto X25519 (KeyAgreement "X25519", "BC") mediante HKDF-SHA256 antes de derivar la clave de sesión.

    /** Firma heredada con SHA-1: colisiones prácticas, prohibida al firmar. */
    public byte[] firmarOrdenHeredada(byte[] orden, PrivateKey clave) throws GeneralSecurityException {
        Signature firma = Signature.getInstance("SHA1withRSA");
        firma.initSign(clave);
        firma.update(orden);
        return firma.sign();
    }

    // Firma híbrida Ed25519 + ML-DSA-65 (FIPS 204). El verificador debe validar AMBAS firmas.
    public byte[] firmarOrden(byte[] orden, PrivateKey claveEd25519, PrivateKey claveMlDsa65) throws GeneralSecurityException {
        Signature firmaClasica = Signature.getInstance("Ed25519", "BC");
        firmaClasica.initSign(claveEd25519);
        firmaClasica.update(orden);
        byte[] sigEd25519 = firmaClasica.sign();

        Signature firmaPqc = Signature.getInstance("ML-DSA", "BCPQC");
        firmaPqc.initSign(claveMlDsa65);
        firmaPqc.update(orden);
        byte[] sigMlDsa65 = firmaPqc.sign();

        // Firma compuesta: [len(Ed25519)][sigEd25519][len(ML-DSA-65)][sigMlDsa65]
        ByteBuffer compuesta = ByteBuffer.allocate(4 + sigEd25519.length + 4 + sigMlDsa65.length);
        compuesta.putInt(sigEd25519.length).put(sigEd25519);
        compuesta.putInt(sigMlDsa65.length).put(sigMlDsa65);
        return compuesta.array();
    }

    /** Recibos para la app móvil: firma híbrida ECDSA P-256 + ML-DSA-65 (FIPS 204). */
    public byte[] firmarRecibo(byte[] recibo) throws GeneralSecurityException {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        // Las claves deben cargarse del KeyStore (ver keyRegenSteps); se generan aquí solo a modo ilustrativo.
        KeyPairGenerator generadorPqc = KeyPairGenerator.getInstance("ML-DSA", "BC");
        generadorPqc.initialize(MLDSAParameterSpec.ml_dsa_65);
        KeyPair parPqc = generadorPqc.generateKeyPair();

        KeyPairGenerator generadorEc = KeyPairGenerator.getInstance("EC");
        generadorEc.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair parEc = generadorEc.generateKeyPair();

        Signature firmaPqc = Signature.getInstance("ML-DSA", "BC");
        firmaPqc.initSign(parPqc.getPrivate());
        firmaPqc.update(recibo);
        byte[] sigPqc = firmaPqc.sign();

        Signature firmaEc = Signature.getInstance("SHA256withECDSA");
        firmaEc.initSign(parEc.getPrivate());
        firmaEc.update(recibo);
        byte[] sigEc = firmaEc.sign();

        // Firma híbrida: [len(sigEc) (4 bytes big-endian)] || sigEc || sigPqc
        ByteBuffer salida = ByteBuffer.allocate(4 + sigEc.length + sigPqc.length);
        salida.putInt(sigEc.length).put(sigEc).put(sigPqc);
        return salida.array();
    }
        firma.update(recibo);
        return firma.sign();
    }
}
