package queincreible.pagos;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import org.junit.jupiter.api.Test;

/** Pruebas: lo débil que aparece aquí solo cuenta como «solo pruebas». */
class FirmaOrdenesTest {

    @Test
    void huellaDeFixtureEsEstable() throws Exception {
        byte[] huella = MessageDigest.getInstance("MD2").digest("fixture".getBytes());
        assertEquals(16, huella.length);
    // La generación automática no estuvo disponible. Aplicar la recomendación PQC indicada sobre el código detectado.
    }
}
