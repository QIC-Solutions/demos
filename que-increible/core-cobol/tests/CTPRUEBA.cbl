       IDENTIFICATION DIVISION.
       PROGRAM-ID. CTPRUEBA.
      *----------------------------------------------------------------
      * Prueba de CTHASH: lo debil de aqui cuenta como solo pruebas.
      *----------------------------------------------------------------
       DATA DIVISION.
       WORKING-STORAGE SECTION.
           COPY CTCOMUN.
       01  CT-CADENA-LARGO         PIC 9(8) COMP VALUE 7.
       01  CT-CADENA               PIC X(7)      VALUE 'FIXTURE'.
       01  CT-ENCADENADO-LARGO     PIC 9(8) COMP VALUE 128.
       01  CT-ENCADENADO           PIC X(128)    VALUE LOW-VALUES.
       01  CT-HASH-LARGO           PIC 9(8) COMP VALUE 20.
       01  CT-HASH                 PIC X(20)     VALUE SPACES.
       PROCEDURE DIVISION.
           CALL 'CSNBOWH' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CUENTA-UNA 'RPMD-160'
               CT-CADENA-LARGO CT-CADENA CT-ENCADENADO-LARGO
               CT-ENCADENADO CT-HASH-LARGO CT-HASH
           GOBACK.
