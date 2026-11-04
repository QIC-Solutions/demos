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
public class FirmaOrdenes {

    /** Par RSA-2048 para las órdenes: vulnerable ante un ordenador cuántico. */
    public KeyPair generarParOrdenes() throws GeneralSecurityException {
        KeyPairGenerator generador = KeyPairGenerator.getInstance("RSA");
        generador.initialize(2048);
        return generador.generateKeyPair();
    }

    /** Par RSA-1024 del canal con el banco adquirente (2011): ya roto hoy. */
    public KeyPair generarParAdquirente() throws GeneralSecurityException {
        KeyPairGenerator generadorAdquirente = KeyPairGenerator.getInstance("RSA");
        generadorAdquirente.initialize(1024);
        return generadorAdquirente.generateKeyPair();
    }

    /** Firma heredada con SHA-1: colisiones prácticas, prohibida al firmar. */
    public byte[] firmarOrdenHeredada(byte[] orden, PrivateKey clave) throws GeneralSecurityException {
        Signature firma = Signature.getInstance("SHA1withRSA");
        firma.initSign(clave);
        firma.update(orden);
        return firma.sign();
    }

    public byte[] firmarOrden(byte[] orden, PrivateKey clave) throws GeneralSecurityException {
        Signature firma = Signature.getInstance("SHA256withRSA");
        firma.initSign(clave);
        firma.update(orden);
        return firma.sign();
    }

    /** Recibos para la app móvil: ECDSA sobre P-256. */
    public byte[] firmarRecibo(byte[] recibo) throws GeneralSecurityException {
        KeyPairGenerator generador = KeyPairGenerator.getInstance("EC");
        generador.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair par = generador.generateKeyPair();
        Signature firma = Signature.getInstance("SHA256withECDSA");
        firma.initSign(par.getPrivate());
        firma.update(recibo);
        return firma.sign();
    }
}
