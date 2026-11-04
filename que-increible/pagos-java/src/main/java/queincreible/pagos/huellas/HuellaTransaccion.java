package queincreible.pagos.huellas;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Huellas de las transacciones para deduplicar y para el webhook de comercios. */
public class HuellaTransaccion {

    /** Secreto HMAC del webhook, en el código (ficticio). */
    private static final String HMAC_SECRET = "qic-demo-webhook-NO-REAL-7f3a9c";

    /** Deduplicación: MD5 (roto, aunque aquí «solo» deduplique). */
    public byte[] huellaRapida(byte[] transaccion) throws GeneralSecurityException {
        return MessageDigest.getInstance("MD5").digest(transaccion);
    }

    /** Identificador de lote, heredado de la v1: SHA-1. */
    public byte[] idLote(byte[] lote) throws GeneralSecurityException {
        return MessageDigest.getInstance("SHA-1").digest(lote);
    }

    public byte[] firmaWebhook(byte[] cuerpo) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(HMAC_SECRET.getBytes(), "HmacSHA256"));
        return mac.doFinal(cuerpo);
    }
}
