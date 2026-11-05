* Que Increible Compañia SL (empresa ficticia de demo).
* Remesas SEPA de pagos a proveedores: firma PKCS #7 con SSF y sobre
* cifrado para el banco. El algoritmo del sobre se elige en la tabla de
* parametrización ZQI_PARAM_CRIPTO (agilidad), salvo en la firma heredada.
REPORT zqi_remesas_sepa.

DATA gv_resumen_firma TYPE ssfhashalg VALUE 'SHA1'.

START-OF-SELECTION.
  PERFORM firmar_remesa.
  PERFORM cifrar_remesa.

FORM firmar_remesa.
  DATA: lt_entrada  TYPE STANDARD TABLE OF ssfbin,
        lt_firmada  TYPE STANDARD TABLE OF ssfbin,
        lt_firmante TYPE STANDARD TABLE OF ssfinfo.
  " Resumen quantum/colision-safe: SHA-256 (usar 'SHA384' para conservación a largo plazo)
  CONSTANTS: lc_resumen_firma TYPE ssfhash VALUE 'SHA256'.
  gv_resumen_firma = lc_resumen_firma.
  CALL FUNCTION 'SSF_KRN_SIGN'
    EXPORTING
      str_format  = 'PKCS7'
      str_hashalg = gv_resumen_firma
    TABLES
      ostr_input_data  = lt_entrada
      signer           = lt_firmante
      ostr_signed_data = lt_firmada.
ENDFORM.

FORM cifrar_remesa.
  DATA: lt_entrada TYPE STANDARD TABLE OF ssfbin,
        lt_sobre   TYPE STANDARD TABLE OF ssfbin,
        lt_destino TYPE STANDARD TABLE OF ssfinfo,
        lv_cifrado TYPE ssfsymalg,
        lv_kem     TYPE string,
        lv_kdf     TYPE string.
  " Sobre híbrido post-cuántico (FIPS 203): X25519 + ML-KEM-768 -> HKDF -> AES-256-GCM.
  " SSF_KRN_ENVELOPE/PKCS7 (RSA/ECDH) queda retirado para SEPA.
  SELECT SINGLE valor FROM zqi_param_cripto INTO @lv_cifrado WHERE clave = 'SOBRE_SEPA'.      " 'AES256-GCM'
  SELECT SINGLE valor FROM zqi_param_cripto INTO @lv_kem     WHERE clave = 'SOBRE_SEPA_KEM'.  " 'X25519+ML-KEM-768'
  SELECT SINGLE valor FROM zqi_param_cripto INTO @lv_kdf     WHERE clave = 'SOBRE_SEPA_KDF'.  " 'HKDF-SHA256'
  " ZQI_PQC_ENVELOPE delega en el servicio Java zqi-pqc-envelope (Bouncy Castle, provider BCPQC)
  " vía RFC/HTTP; recibe las claves públicas ML-KEM-768 y X25519 del destinatario desde zqi_pqc_keys.
  CALL FUNCTION 'ZQI_PQC_ENVELOPE'
    EXPORTING
      str_format       = 'CMS_HYBRID_KEM'
      str_kem_alg      = lv_kem
      str_kdf_alg      = lv_kdf
      str_sym_encr_alg = lv_cifrado
    TABLES
      ostr_input_data     = lt_entrada
      recipient_list      = lt_destino
      ostr_enveloped_data = lt_sobre.
ENDFORM.

FORM huella_fichero USING iv_fichero TYPE string.
  DATA lv_huella TYPE hash160.
  CALL FUNCTION 'MD5_CALCULATE_HASH_FOR_CHAR'
    EXPORTING
      data = iv_fichero
    IMPORTING
      hash = lv_huella.
ENDFORM.
