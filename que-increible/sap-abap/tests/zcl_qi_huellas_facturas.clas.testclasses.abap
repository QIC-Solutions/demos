* Pruebas unitarias (ABAP Unit): lo débil de aquí cuenta como «solo pruebas».
CLASS ltc_huellas DEFINITION FINAL FOR TESTING RISK LEVEL HARMLESS DURATION SHORT.
  PRIVATE SECTION.
    METHODS hmac_md5_fixture FOR TESTING.
ENDCLASS.

CLASS ltc_huellas IMPLEMENTATION.
  METHOD hmac_md5_fixture.
    DATA lv_huella TYPE string.
    CALL FUNCTION 'CALCULATE_HMAC_FOR_RAW'
      EXPORTING
        alg  = 'MD5'
        data = 'fixture'
      IMPORTING
        hmacstring = lv_huella.
    cl_abap_unit_assert=>assert_not_initial( lv_huella ).
  ENDMETHOD.
ENDCLASS.
