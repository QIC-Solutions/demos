package queincreible.pagos.pqc;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;

/**
 * Piloto post-cuántico (2026): la clave de sesión con el nuevo procesador de
 * pagos se acuerda con ML-KEM-768 y las liquidaciones se firman con ML-DSA-65,
 * con Bouncy Castle 1.79.
 */
public class CanalPostCuantico {

    private final SecureRandom aleatorio = new SecureRandom();

    public SecretWithEncapsulation encapsularSesion(MLKEMKeyParameters clavePublicaProcesador) {
        MLKEMGenerator generador = new MLKEMGenerator(aleatorio);
        return generador.generateEncapsulated(clavePublicaProcesador);
    }

    public MLKEMKeyParameters parametrosSesion() {
        return new MLKEMKeyParameters(false, MLKEMParameters.ml_kem_768);
    }

    public byte[] firmarLiquidacion(byte[] liquidacion) throws Exception {
        MLDSASigner firmante = new MLDSASigner();
        firmante.init(true, new MLDSAKeyParameters(true, MLDSAParameters.ml_dsa_65));
        firmante.update(liquidacion, 0, liquidacion.length);
        return firmante.generateSignature();
    }

    /** Lo mismo por la JCA, con el proveedor de Bouncy Castle. */
    public byte[] firmarConJca(byte[] datos) throws GeneralSecurityException {
        KeyPairGenerator generador = KeyPairGenerator.getInstance("ML-DSA", "BC");
        KeyPair par = generador.generateKeyPair();
        Signature firma = Signature.getInstance("ML-DSA", "BC");
        firma.initSign(par.getPrivate());
        firma.update(datos);
        return firma.sign();
    }
}
