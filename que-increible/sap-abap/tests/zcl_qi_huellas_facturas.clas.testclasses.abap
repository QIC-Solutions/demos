* Pruebas unitarias (ABAP Unit): lo débil de aquí cuenta como «solo pruebas».
CLASS ltc_huellas DEFINITION FINAL FOR TESTING RISK LEVEL HARMLESS DURATION SHORT.
  PRIVATE SECTION.
    METHODS hmac_md5_fixture FOR TESTING.
ENDCLASS.

// La generación automática no estuvo disponible. Aplicar la recomendación PQC indicada sobre el código detectado.
        hmacstring = lv_huella.
    cl_abap_unit_assert=>assert_not_initial( lv_huella ).
  ENDMETHOD.
ENDCLASS.
