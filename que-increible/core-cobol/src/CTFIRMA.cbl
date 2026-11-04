       IDENTIFICATION DIVISION.
       PROGRAM-ID. CTFIRMA.
      *----------------------------------------------------------------
      * Que Increible Compania SL (empresa ficticia de demo).
      * Firma del cierre contable mensual y cifrado de la clave de
      * sesion con el banco: servicios de clave publica de ICSF.
      * Desde 2026, piloto con ML-DSA (QSA) en el CCA 8.
      *----------------------------------------------------------------
       ENVIRONMENT DIVISION.
       DATA DIVISION.
       WORKING-STORAGE SECTION.
           COPY CTCOMUN.
       01  CT-TIPO-RSA             PIC X(8)  VALUE 'RSA-CRT '.
       01  CT-TIPO-ECC             PIC X(8)  VALUE 'ECC-PAIR'.
       01  CT-TIPO-QSA             PIC X(16) VALUE 'QSA-PAIR'.
       01  CT-ESTRUCTURA-RSA.
           05  CT-RSA-BITS         PIC 9(4) COMP VALUE 2048.
           05  CT-RSA-N-LARGO      PIC 9(4) COMP VALUE 0.
           05  CT-RSA-E-LARGO      PIC 9(4) COMP VALUE 3.
           05  FILLER              PIC X(14) VALUE LOW-VALUES.
           05  CT-RSA-EXPONENTE    PIC X(3)  VALUE X'010001'.
       01  CT-RSA-LARGO            PIC 9(8) COMP VALUE 23.
       01  CT-ESTRUCTURA-ECC.
           05  CT-ECC-TIPO         PIC X     VALUE X'00'.
           05  FILLER              PIC X     VALUE LOW-VALUE.
           05  CT-ECC-BITS         PIC 9(4) COMP VALUE 256.
           05  CT-ECC-D-LARGO      PIC 9(4) COMP VALUE 0.
           05  CT-ECC-Q-LARGO      PIC 9(4) COMP VALUE 0.
       01  CT-ECC-LARGO            PIC 9(8) COMP VALUE 8.
      * ML-DSA (6,5): el algoritmo X'05' y los parametros X'0605'.
       01  CT-ESTRUCTURA-QSA.
           05  CT-QSA-ALGORITMO    PIC X     VALUE X'05'.
           05  CT-QSA-FORMATO      PIC X     VALUE X'00'.
           05  CT-QSA-PARAMETROS   PIC X(2)  VALUE X'0605'.
           05  CT-QSA-CLAVE-LARGO  PIC 9(4) COMP VALUE 0.
           05  FILLER              PIC X(2)  VALUE LOW-VALUES.
       01  CT-QSA-LARGO            PIC 9(8) COMP VALUE 8.
       01  CT-ESQUELETO-LARGO      PIC 9(8) COMP VALUE 3500.
       01  CT-ESQUELETO            PIC X(3500)   VALUE LOW-VALUES.
       01  CT-CLAVE-LARGO          PIC 9(8) COMP VALUE 3500.
       01  CT-CLAVE                PIC X(3500)   VALUE LOW-VALUES.
       01  CT-PUBLICA              PIC X(3500)   VALUE LOW-VALUES.
       01  CT-HASH-LARGO           PIC 9(8) COMP VALUE 20.
       01  CT-HASH                 PIC X(64)     VALUE SPACES.
       01  CT-FIRMA-LARGO          PIC 9(8) COMP VALUE 512.
       01  CT-FIRMA-BITS           PIC 9(8) COMP VALUE 0.
       01  CT-FIRMA                PIC X(512)    VALUE SPACES.
      * Firma del cierre: PKCS #1 v1.5 con SHA-1 (heredada de 2008).
       01  CT-REGLAS-FIRMA         PIC X(32)
                         VALUE 'RSA     PKCS-1.1HASH    SHA-1   '.
       01  CT-REGLAS-ECDSA         PIC X(24)
                         VALUE 'ECDSA   SHA-256 MESSAGE '.
       01  CT-REGLAS-PKE           PIC X(8)  VALUE 'PKCS-1.2'.
       01  CT-REGLAS-EDH           PIC X(8)  VALUE 'DERIV01 '.
       01  CT-BITS-DERIVADOS       PIC 9(8) COMP VALUE 256.
       PROCEDURE DIVISION.
       PRINCIPAL.
           PERFORM CLAVES
           PERFORM FIRMAR-CIERRE
           PERFORM CLAVE-SESION-BANCO
           GOBACK.
       CLAVES.
           CALL 'CSNDPKB' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CUENTA-UNA CT-TIPO-RSA
               CT-RSA-LARGO CT-ESTRUCTURA-RSA CT-CERO CT-AREA
               CT-CERO CT-AREA CT-CERO CT-AREA CT-CERO CT-AREA
               CT-CERO CT-AREA CT-CERO CT-AREA
               CT-ESQUELETO-LARGO CT-ESQUELETO
           CALL 'CSNDPKB' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CUENTA-UNA CT-TIPO-ECC
               CT-ECC-LARGO CT-ESTRUCTURA-ECC CT-CERO CT-AREA
               CT-CERO CT-AREA CT-CERO CT-AREA CT-CERO CT-AREA
               CT-CERO CT-AREA CT-CERO CT-AREA
               CT-ESQUELETO-LARGO CT-ESQUELETO
           CALL 'CSNDPKB' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CUENTA-UNA CT-TIPO-QSA
               CT-QSA-LARGO CT-ESTRUCTURA-QSA CT-CERO CT-AREA
               CT-CERO CT-AREA CT-CERO CT-AREA CT-CERO CT-AREA
               CT-CERO CT-AREA CT-CERO CT-AREA
               CT-CLAVE-LARGO CT-PUBLICA.
       FIRMAR-CIERRE.
           CALL 'CSNDDSG' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CUENTA-CUATRO CT-REGLAS-FIRMA
               CT-CLAVE-LARGO CT-CLAVE CT-HASH-LARGO CT-HASH
               CT-FIRMA-LARGO CT-FIRMA-BITS CT-FIRMA
           CALL 'CSNDDSG' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CUENTA-TRES CT-REGLAS-ECDSA
               CT-CLAVE-LARGO CT-CLAVE CT-HASH-LARGO CT-HASH
               CT-FIRMA-LARGO CT-FIRMA-BITS CT-FIRMA.
       CLAVE-SESION-BANCO.
           CALL 'CSNDPKE' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CUENTA-UNA CT-REGLAS-PKE
               CT-HASH-LARGO CT-HASH CT-CERO CT-AREA
               CT-CLAVE-LARGO CT-PUBLICA CT-FIRMA-LARGO CT-FIRMA
           CALL 'CSNDEDH' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CUENTA-UNA CT-REGLAS-EDH
               CT-CLAVE-LARGO CT-CLAVE CT-CERO CT-AREA
               CT-CLAVE-LARGO CT-PUBLICA CT-CERO CT-AREA
               CT-CERO CT-AREA CT-BITS-DERIVADOS CT-CERO CT-AREA
               CT-CERO CT-AREA CT-CERO CT-AREA CT-CERO CT-AREA
               CT-CERO CT-AREA CT-CERO CT-AREA CT-CLAVE-LARGO
               CT-CLAVE.
