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
    }

    @Test
    void cifradoAesGcmDelSimuladorDeTerminal() throws Exception {
        KeyGenerator generador = KeyGenerator.getInstance("AES");
        generador.init(256);
        byte[] nonce = new byte[12];
        SecureRandom.getInstanceStrong().nextBytes(nonce);
        Cipher cifrador = Cipher.getInstance("AES/GCM/NoPadding");
        cifrador.init(Cipher.ENCRYPT_MODE, generador.generateKey(), new GCMParameterSpec(128, nonce));
        // 4 bytes de texto en claro + 16 bytes de etiqueta de autenticación GCM
        assertEquals(4 + 16, cifrador.doFinal("1234".getBytes()).length);
    }
}
