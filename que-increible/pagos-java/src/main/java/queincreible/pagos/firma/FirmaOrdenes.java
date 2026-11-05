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
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;

public class FirmaOrdenes {

    static {
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());
        if (Security.getProvider("BCPQC") == null) Security.addProvider(new BouncyCastlePQCProvider());
    }

    /** Par ML-KEM-768 (FIPS 203) para las órdenes: resistente a ordenadores cuánticos. */
    public KeyPair generarParOrdenes() throws GeneralSecurityException {
        KeyPairGenerator generador = KeyPairGenerator.getInstance("ML-KEM", "BCPQC");
        generador.initialize(MLKEMParameterSpec.ml_kem_768, new SecureRandom());
        return generador.generateKeyPair();
    }

    /** Componente clásica del esquema híbrido X25519 + ML-KEM-768. */
    public KeyPair generarParX25519() throws GeneralSecurityException {
        KeyPairGenerator generador = KeyPairGenerator.getInstance("X25519", "BC");
        return generador.generateKeyPair();
    }

    /** Emisor: encapsula un secreto ML-KEM-768 hacia la clave pública del receptor. */
    public SecretKeyWithEncapsulation encapsular(PublicKey pubMlKem) throws GeneralSecurityException {
        KeyGenerator kg = KeyGenerator.getInstance("ML-KEM", "BCPQC");
        kg.init(new KEMGenerateSpec(pubMlKem, "AES"), new SecureRandom());
        return (SecretKeyWithEncapsulation) kg.generateKey();
    }

    /** Receptor: recupera el secreto ML-KEM-768 a partir del encapsulado. */
    public SecretKey desencapsular(PrivateKey privMlKem, byte[] encapsulado) throws GeneralSecurityException {
        KeyGenerator kg = KeyGenerator.getInstance("ML-KEM", "BCPQC");
        kg.init(new KEMExtractSpec(privMlKem, encapsulado, "AES"), new SecureRandom());
        return kg.generateKey();
    }

    /** Híbrido: combina el secreto X25519 y el de ML-KEM-768 vía HKDF-SHA256 en una clave AES-256. */
    public SecretKey combinarSecretos(byte[] secretoX25519, byte[] secretoMlKem) throws GeneralSecurityException {
        byte[] ikm = new byte[secretoX25519.length + secretoMlKem.length];
        System.arraycopy(secretoX25519, 0, ikm, 0, secretoX25519.length);
        System.arraycopy(secretoMlKem, 0, ikm, secretoX25519.length, secretoMlKem.length);
        org.bouncycastle.crypto.generators.HKDFBytesGenerator hkdf =
            new org.bouncycastle.crypto.generators.HKDFBytesGenerator(new org.bouncycastle.crypto.digests.SHA256Digest());
        hkdf.init(new org.bouncycastle.crypto.params.HKDFParameters(ikm, null, "ordenes-x25519-mlkem768".getBytes()));
        byte[] clave = new byte[32];
        hkdf.generateBytes(clave, 0, 32);
        return new SecretKeySpec(clave, "AES");
    }

    /** Par ML-KEM-768 (FIPS 203) del canal con el banco adquirente, vía Bouncy Castle (provider BCPQC). */
    public KeyPair generarParAdquirente() throws GeneralSecurityException {
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        KeyPairGenerator generadorAdquirente = KeyPairGenerator.getInstance("ML-KEM", "BCPQC");
        generadorAdquirente.initialize(MLKEMParameterSpec.ml_kem_768, new SecureRandom());
        return generadorAdquirente.generateKeyPair();
    }

    /** Par X25519 clásico para el esquema híbrido X25519 + ML-KEM-768 (secretos combinados vía HKDF). */
    public KeyPair generarParAdquirenteClasico() throws GeneralSecurityException {
        KeyPairGenerator generadorClasico = KeyPairGenerator.getInstance("X25519");
        return generadorClasico.generateKeyPair();
    }

    /** Encapsula un secreto compartido ML-KEM-768 hacia la clave pública del adquirente. */
    public SecretKeyWithEncapsulation encapsularParaAdquirente(PublicKey publicaAdquirente) throws GeneralSecurityException {
        KeyGenerator generadorSecreto = KeyGenerator.getInstance("ML-KEM", "BCPQC");
        generadorSecreto.init(new KEMGenerateSpec(publicaAdquirente, "Secret"), new SecureRandom());
        return (SecretKeyWithEncapsulation) generadorSecreto.generateKey();
    }

    /** Desencapsula el secreto compartido ML-KEM-768 con la clave privada propia. */
    public SecretKeyWithEncapsulation desencapsularDeAdquirente(PrivateKey privadaPropia, byte[] encapsulado) throws GeneralSecurityException {
        KeyGenerator generadorSecreto = KeyGenerator.getInstance("ML-KEM", "BCPQC");
        generadorSecreto.init(new KEMExtractSpec(privadaPropia, encapsulado, "Secret"), new SecureRandom());
        return (SecretKeyWithEncapsulation) generadorSecreto.generateKey();
    }

    /** Firma con SHA-256: sustituye SHA-1 (deprecado por NIST, colisiones prácticas). */
    public byte[] firmarOrden(byte[] orden, PrivateKey clave) throws GeneralSecurityException {
        Signature firma = Signature.getInstance("SHA256withRSA");
        firma.initSign(clave);
        firma.update(orden);
        return firma.sign();
    }

    // Requiere registrar los providers al arrancar:
    // Security.addProvider(new BouncyCastleProvider());
    // Security.addProvider(new BouncyCastlePQCProvider());
    public byte[] firmarOrden(byte[] orden, PrivateKey claveMlDsa, PrivateKey claveEd25519) throws GeneralSecurityException {
        // Firma post-cuántica ML-DSA-65 (FIPS 204)
        Signature firmaPqc = Signature.getInstance("ML-DSA", "BCPQC");
        firmaPqc.initSign(claveMlDsa);
        firmaPqc.update(orden);
        byte[] sigPqc = firmaPqc.sign();

        // Firma clásica Ed25519 (esquema híbrido durante la migración)
        Signature firmaClasica = Signature.getInstance("Ed25519", "BC");
        firmaClasica.initSign(claveEd25519);
        firmaClasica.update(orden);
        byte[] sigClasica = firmaClasica.sign();

        // Firma compuesta: [int32 len(sigClasica)][sigClasica][sigPqc]; el verificador debe validar AMBAS
        ByteBuffer buf = ByteBuffer.allocate(4 + sigClasica.length + sigPqc.length);
        buf.putInt(sigClasica.length).put(sigClasica).put(sigPqc);
        return buf.array();
    }

    /** Recibos para la app móvil: ML-DSA-65 (FIPS 204, post-cuántico). */
    public byte[] firmarRecibo(byte[] recibo) throws GeneralSecurityException {
        // La clave debe cargarse desde el almacén de claves, no generarse en cada firma.
        KeyPairGenerator generador = KeyPairGenerator.getInstance("ML-DSA", "BCPQC");
        generador.initialize(MLDSAParameterSpec.ml_dsa_65);
        KeyPair par = generador.generateKeyPair();
        Signature firma = Signature.getInstance("ML-DSA", "BCPQC");
        firma.initSign(par.getPrivate());
        firma.update(recibo);
        return firma.sign();
    }
}
