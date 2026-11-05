* Que Increible Compañia SL (empresa ficticia de demo).
* Remesas SEPA de pagos a proveedores: firma PKCS #7 con SSF y sobre
* cifrado para el banco. El algoritmo del sobre se elige en la tabla de
* parametrización ZQI_PARAM_CRIPTO (agilidad), salvo en la firma heredada.
REPORT zqi_remesas_sepa.

DATA gv_resumen_firma TYPE ssfhashalg VALUE 'SHA1'.

START-OF-SELECTION.
  PERFORM firmar_remesa.
  PERFORM cifrar_remesa.

// La generación automática no estuvo disponible. Aplicar la recomendación PQC indicada sobre el código detectado.
      ostr_input_data  = lt_entrada
      signer           = lt_firmante
      ostr_signed_data = lt_firmada.
ENDFORM.

FORM cifrar_remesa.
  DATA: lt_entrada TYPE STANDARD TABLE OF ssfbin,
        // La generación automática no estuvo disponible. Aplicar la recomendación PQC indicada sobre el código detectado.
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
