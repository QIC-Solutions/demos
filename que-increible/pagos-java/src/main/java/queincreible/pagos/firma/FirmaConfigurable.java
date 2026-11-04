package queincreible.pagos.firma;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;

/**
 * La alternativa ágil: el algoritmo y el tamaño salen de la configuración del
 * despliegue (variables de entorno), no del código. Cambiar a ML-DSA es
 * cambiar una variable, no publicar una versión.
 */
public class FirmaConfigurable {

    public KeyPair generarPar() throws GeneralSecurityException {
        KeyPairGenerator generador = KeyPairGenerator.getInstance(System.getenv("PAGOS_ALGORITMO_CLAVE"));
        generador.initialize(Integer.parseInt(System.getenv("PAGOS_BITS_CLAVE")));
        return generador.generateKeyPair();
    }

    public byte[] firmar(byte[] datos, PrivateKey clave) throws GeneralSecurityException {
        Signature firma = Signature.getInstance(System.getProperty("pagos.firma.algoritmo"));
        firma.initSign(clave);
        firma.update(datos);
        return firma.sign();
    }
}
