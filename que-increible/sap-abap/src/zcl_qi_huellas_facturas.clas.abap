* Que Increible Compañia SL (empresa ficticia de demo).
* Extensión SAP FI: huellas de las facturas electrónicas y firma de los
* avisos de pago a proveedores. La criptografía débil está A PROPÓSITO.
CLASS zcl_qi_huellas_facturas DEFINITION PUBLIC FINAL CREATE PUBLIC.
  PUBLIC SECTION.
    CONSTANTS co_alg_factura TYPE string VALUE 'SHA256'.
    CONSTANTS co_alg_legado TYPE string VALUE 'MD5'.
    METHODS huella_factura IMPORTING iv_texto TYPE string RETURNING VALUE(rv_huella) TYPE string.
    METHODS huella_proveedor IMPORTING iv_texto TYPE string RETURNING VALUE(rv_huella) TYPE string.
    METHODS huella_legada IMPORTING iv_datos TYPE xstring RETURNING VALUE(rv_huella) TYPE string.
    METHODS firmar_aviso IMPORTING iv_texto TYPE string RETURNING VALUE(rv_firma) TYPE string.
    METHODS firmar_sesion IMPORTING iv_clave TYPE xstring.
ENDCLASS.

CLASS zcl_qi_huellas_facturas IMPLEMENTATION.
  METHOD huella_factura.
    cl_abap_message_digest=>calculate_hash_for_char(
      EXPORTING if_algorithm  = co_alg_factura
                if_data       = iv_texto
      IMPORTING ef_hashstring = rv_huella ).
  ENDMETHOD.

  METHOD huella_proveedor.
    " Sin if_algorithm: SHA-1, el valor por defecto de SAP.
    cl_abap_message_digest=>calculate_hash_for_char(
      EXPORTING if_data       = iv_texto
      IMPORTING ef_hashstring = rv_huella ).
  ENDMETHOD.

  METHOD huella_legada.
    CALL METHOD cl_abap_message_digest=>calculate_hash_for_raw
      EXPORTING if_algorithm  = co_alg_legado
                if_data       = iv_datos
      IMPORTING ef_hashstring = rv_huella.
  ENDMETHOD.

  METHOD firmar_aviso.
    DATA lv_hmac_secret TYPE string.
    " DEMO: secreto HMAC escrito en el código (ficticio).
    lv_hmac_secret = 'sap-que-increible-demo-NO-REAL'.
    cl_abap_hmac=>calculate_hmac_for_char(
      EXPORTING if_algorithm  = 'SHA256'
                if_key        = cl_abap_hmac=>string_to_xstring( lv_hmac_secret )
                if_data       = iv_texto
      IMPORTING ef_hmacstring = rv_firma ).
  ENDMETHOD.

  METHOD firmar_sesion.
    " get_instance con algoritmo explícito: HMAC-SHA-256 (nunca confiar en el default SHA-1).
    " Para huellas de larga duración usar if_algorithm = 'SHA512'.
    DATA(lo_hmac) = cl_abap_hmac=>get_instance(
                      if_algorithm = 'SHA256'
                      if_key       = iv_clave ).
    lo_hmac->final( ).
  ENDMETHOD.
ENDCLASS.
