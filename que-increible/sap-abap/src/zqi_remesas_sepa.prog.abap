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
  " Resumen SHA-256 (FIPS 180-4); usar 'SHA384' para firmas de larga duración
  CONSTANTS: lc_resumen_firma TYPE ssfparms-hashalg VALUE 'SHA256'.
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
        lv_kem     TYPE string,
        lv_cifrado TYPE string.
  " Parámetros PQC: KEM híbrido (X25519 + ML-KEM-768, FIPS 203) y cifrado simétrico
  SELECT SINGLE valor FROM zqi_param_cripto INTO @lv_kem     WHERE clave = 'SOBRE_SEPA_KEM'.   " 'X25519+ML-KEM-768'
  SELECT SINGLE valor FROM zqi_param_cripto INTO @lv_cifrado WHERE clave = 'SOBRE_SEPA_SYM'.   " 'AES-256-GCM'
  " El envelope PKCS7 (RSA/EC) se sustituye por un sobre híbrido PQC generado en el servicio
  " ZQI_PQC_ENVELOPE (SAP Java/JCo con Bouncy Castle 1.78, provider BCPQC)
  CALL FUNCTION 'ZQI_PQC_ENVELOPE' DESTINATION 'QI_PQC_BC_SERVICE'
    EXPORTING
      str_format       = 'HYBRID_KEM_CMS'
      str_kem_alg      = lv_kem
      str_sym_encr_alg = lv_cifrado
    TABLES
      ostr_input_data     = lt_entrada
      recipient_list      = lt_destino
      ostr_enveloped_data = lt_sobre.
ENDFORM.

FORM huella_fichero USING iv_fichero TYPE string.
  DATA lv_huella TYPE string.
  " SHA-256 (usar 'SHA384' si la huella debe conservarse a largo plazo)
  CALL FUNCTION 'CALCULATE_HASH_FOR_CHAR'
    EXPORTING
      alg        = 'SHA256'
      data       = iv_fichero
    IMPORTING
      hashstring = lv_huella
    EXCEPTIONS
      unknown_alg = 1
      param_error = 2
      internal_error = 3
      OTHERS      = 4.
  IF sy-subrc <> 0.
    MESSAGE e398(00) WITH 'Error al calcular la huella SHA-256 del fichero'.
  ENDIF.
ENDFORM.
