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
    " Versión de 2012: sin algorithm, 3DES-CBC (el valor por defecto de SAP).
    cl_sec_sxml_writer=>encrypt(
      EXPORTING plaintext  = iv_datos
                key        = iv_clave
      IMPORTING ciphertext = lv_cifrado ).
    " Versión nueva: AES-256-CBC.
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
