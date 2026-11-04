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
    void cifradoRc4DelSimuladorDeTerminal() throws Exception {
        KeyGenerator generador = KeyGenerator.getInstance("RC4");
        generador.init(128);
        Cipher cifrador = Cipher.getInstance("RC4");
        cifrador.init(Cipher.ENCRYPT_MODE, generador.generateKey());
        assertEquals(4, cifrador.doFinal("1234".getBytes()).length);
    }
}
