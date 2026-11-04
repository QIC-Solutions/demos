package queincreible.pagos.tls;

import java.security.GeneralSecurityException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/**
 * Conexión con el banco adquirente. Su pasarela de 2012 solo acepta TLS 1.0,
 * así que el cliente se fija a esa versión (retirada por el RFC 8996).
 */
public class ClienteAdquirente {

    public SSLContext contextoHeredado() throws GeneralSecurityException {
        SSLContext contexto = SSLContext.getInstance("TLSv1");
        contexto.init(null, null, null);
        return contexto;
    }

    public void limitarProtocolos(SSLSocket socket) {
        socket.setEnabledProtocols(new String[] {"TLSv1", "TLSv1.1"});
        socket.setEnabledCipherSuites(new String[] {"TLS_RSA_WITH_3DES_EDE_CBC_SHA", "SSL_RSA_WITH_RC4_128_SHA"});
    }

    public SSLContext contextoActual() throws GeneralSecurityException {
        SSLContext contexto = SSLContext.getInstance("TLSv1.3");
        contexto.init(null, null, null);
        return contexto;
    }
}
