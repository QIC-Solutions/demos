package queincreible.pagos.claves;

/**
 * DEMO — criptografía incrustada: la clave privada con la que se firmaban los
 * extractos para comercios, pegada en el código en 2019 «de forma provisional».
 *
 * La clave es FICTICIA: se generó solo para esta demo, no protege nada y no
 * corresponde a ningún certificado real. Está aquí para que |QS>EDR la encuentre.
 */
final class ClaveFirmaComercios {

    static final String CLAVE_PRIVADA_PEM = """
            -----BEGIN PRIVATE KEY-----
            MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAwQIC0FICTICIA0DEMO0QIC0NO0
            VALIDA0SOLO0PARA0QSEDR0que0increible0example0000000000000000000000000000000
            -----END PRIVATE KEY-----
            """;

    /** Secreto con el que se firman los JWT del portal de comercios (ficticio). */
    static final String JWT_SECRET = "que-increible-demo-jwt-secreto-NO-REAL";

    private ClaveFirmaComercios() {}
}
