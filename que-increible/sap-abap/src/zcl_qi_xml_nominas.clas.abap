* Que Increible Compañia SL (empresa ficticia de demo).
* Cifrado XML de las nóminas que SAP HCM envía al backoffice.
CLASS zcl_qi_xml_nominas DEFINITION PUBLIC FINAL CREATE PUBLIC.
  PUBLIC SECTION.
    METHODS cifrar IMPORTING iv_datos TYPE xstring iv_clave TYPE xstring.
    METHODS sellar IMPORTING iv_datos TYPE xstring iv_clave TYPE xstring.
ENDCLASS.

CLASS zcl_qi_xml_nominas IMPLEMENTATION.
  METHOD cifrar.
    DATA lv_cifrado TYPE xstring.
    DATA lv_mac     TYPE xstring.
    " Remediado: AES-256 explícito (PEM => IV aleatorio generado y prefijado por SAP).
    " iv_clave debe ser una clave AES-256 (32 bytes) nueva, distinta de la antigua 3DES.
    cl_sec_sxml_writer=>encrypt(
      EXPORTING plaintext  = iv_datos
                key        = iv_clave
                algorithm  = cl_sec_sxml_writer=>co_aes256_algorithm_pem
      IMPORTING ciphertext = lv_cifrado ).
    " Cifrado autenticado (encrypt-then-MAC) con HMAC-SHA256 y clave MAC independiente (32 bytes).
    cl_abap_hmac=>calculate_hmac_for_raw(
      EXPORTING if_algorithm     = 'SHA256'
                if_key           = iv_clave_mac
                if_data          = lv_cifrado
      IMPORTING ef_hmacxstring   = lv_mac ).
    " Salida: ciphertext || HMAC (verificar el HMAC antes de descifrar).
    rv_resultado = lv_cifrado && lv_mac.
  ENDMETHOD.
ENDCLASS.
    cl_sec_sxml_writer=>encrypt(
      EXPORTING plaintext  = iv_datos
                key        = iv_clave
                algorithm  = cl_sec_sxml_writer=>co_aes256_algorithm
      IMPORTING ciphertext = lv_cifrado ).
  ENDMETHOD.

  METHOD sellar.
    DATA(lv_sello) = cl_sec_sxml_writer=>hmac(
      hash_algorithm = cl_sec_sxml_writer=>co_alg_sha256
      key            = iv_clave
      input          = iv_datos ).
  ENDMETHOD.
ENDCLASS.
