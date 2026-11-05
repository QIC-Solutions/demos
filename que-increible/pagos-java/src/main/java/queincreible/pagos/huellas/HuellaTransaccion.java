package queincreible.pagos.huellas;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Huellas de las transacciones para deduplicar y para el webhook de comercios. */
public class HuellaTransaccion {

    /** Secreto HMAC del webhook, en el código (ficticio). */
    private static final String HMAC_SECRET = "qic-demo-webhook-NO-REAL-7f3a9c";

    /** Algoritmo de huella (SHA-256, FIPS 180-4). Usar "SHA-384" si la huella debe perdurar frente a atacantes cuánticos. */
    private static final String ALGORITMO_HUELLA = "SHA-256";

    /** Deduplicación: SHA-256 (resistente a colisiones; sustituye a MD5). */
    public byte[] huellaRapida(byte[] transaccion) throws GeneralSecurityException {
        return MessageDigest.getInstance(ALGORITMO_HUELLA).digest(transaccion);
    }

    /** Identificador de lote, heredado de la v1: SHA-1 (pendiente de migración a SHA-256 en el mismo cambio). */
    public byte[] idLote(byte[] lote) throws GeneralSecurityException {
        return MessageDigest.getInstance("SHA-1").digest(lote);
    }

    public byte[] firmaWebhook(byte[] cuerpo) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(HMAC_SECRET.getBytes(), "HmacSHA256"));
        return mac.doFinal(cuerpo);
    }
}
