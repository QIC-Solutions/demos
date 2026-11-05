       IDENTIFICATION DIVISION.
       PROGRAM-ID. CTHASH.
      *----------------------------------------------------------------
      * Que Increible Compania SL (empresa ficticia de demo).
      * Huellas de los ficheros contables y MAC de las remesas.
      *----------------------------------------------------------------
       ENVIRONMENT DIVISION.
       DATA DIVISION.
       WORKING-STORAGE SECTION.
           COPY CTCOMUN.
       01  CT-CADENA-LARGO         PIC 9(8) COMP VALUE 128.
       01  CT-CADENA               PIC X(128)    VALUE SPACES.
       01  CT-ENCADENADO-LARGO     PIC 9(8) COMP VALUE 128.
       01  CT-ENCADENADO           PIC X(128)    VALUE LOW-VALUES.
       01  CT-HASH-LARGO           PIC 9(8) COMP VALUE 64.
       01  CT-HASH                 PIC X(64)     VALUE SPACES.
       01  CT-CLAVE-LARGO          PIC 9(8) COMP VALUE 64.
       01  CT-CLAVE                PIC X(64)     VALUE LOW-VALUES.
      * Huella de deduplicacion de asientos: MD5 (2004).
       01  CT-REGLAS-MD5           PIC X(8)      VALUE 'MD5     '.
       01  CT-REGLAS-SHA1          PIC X(8)      VALUE 'SHA-1   '.
       01  CT-REGLAS-SHA256        PIC X(8)      VALUE 'SHA-256 '.
       01  CT-REGLAS-HMAC.
           01  CT-REGLAS-SHA256.
           05  FILLER              PIC X(8) VALUE 'SHA-256 '.
       01  CT-REGLAS-SHA384.
           05  FILLER              PIC X(8) VALUE 'SHA-384 '.
       01  CT-REGLAS-HMAC.
           05  FILLER              PIC X(8) VALUE 'HMAC    '.
           05  FILLER              PIC X(8) VALUE 'SHA-256 '.
       PROCEDURE DIVISION.
       PRINCIPAL.
      *    MD5 ELIMINADO: SE USA SHA-256 (32 BYTES DE SALIDA)
           MOVE 32 TO CT-HASH-LARGO
           CALL 'CSNBOWH' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CUENTA-UNA CT-REGLAS-SHA256
               CT-CADENA-LARGO CT-CADENA CT-ENCADENADO-LARGO
               CT-ENCADENADO CT-HASH-LARGO CT-HASH
           IF CT-RC NOT = 0
               DISPLAY 'ERROR CSNBOWH RC=' CT-RC ' RAZON=' CT-RAZON
               PERFORM ABORTAR-PROCESO
           END-IF
      *    PARA CONTEXTOS DE LARGA DURACION (RESISTENCIA CUANTICA)
      *    USAR CT-REGLAS-SHA384 Y MOVE 48 TO CT-HASH-LARGO
               CT-SALIDA CT-CUENTA-UNA CT-REGLAS-SHA1
               CT-CADENA-LARGO CT-CADENA CT-ENCADENADO-LARGO
               CT-ENCADENADO CT-HASH-LARGO CT-HASH
           CALL 'CSNBOWH' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CUENTA-UNA CT-REGLAS-SHA256
               CT-CADENA-LARGO CT-CADENA CT-ENCADENADO-LARGO
               CT-ENCADENADO CT-HASH-LARGO CT-HASH
           CALL 'CSNBHMG' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CUENTA-DOS CT-REGLAS-HMAC CT-CLAVE-LARGO
               CT-CLAVE CT-CADENA-LARGO CT-CADENA
               CT-ENCADENADO-LARGO CT-ENCADENADO CT-HASH-LARGO CT-HASH
           GOBACK.
