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
           *    FIRMA HIBRIDA: ED25519 + ML-DSA-65 (FIPS 204)
      *    AMBAS FIRMAS DEBEN VERIFICARSE EN EL RECEPTOR
           MOVE 2                  TO CT-CUENTA-DOS
           MOVE 'EDDSA   '         TO CT-REGLAS-EDDSA(1:8)
           MOVE 'SHA-512 '         TO CT-REGLAS-EDDSA(9:8)
           CALL 'CSNDDSG' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CUENTA-DOS CT-REGLAS-EDDSA
               CT-CLAVE-ED-LARGO CT-CLAVE-ED CT-MSG-LARGO CT-MSG
               CT-FIRMA-ED-LARGO CT-FIRMA-ED-BITS CT-FIRMA-ED
           IF CT-RC NOT = ZERO
               PERFORM ERROR-FIRMA
           END-IF
           MOVE 2                  TO CT-CUENTA-DOS
           MOVE 'CRDL-DSA'         TO CT-REGLAS-MLDSA(1:8)
           MOVE 'CRDLHASH'         TO CT-REGLAS-MLDSA(9:8)
           CALL 'CSNDDSG' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CUENTA-DOS CT-REGLAS-MLDSA
               CT-CLAVE-QSA-LARGO CT-CLAVE-QSA CT-MSG-LARGO CT-MSG
               CT-FIRMA-QSA-LARGO CT-FIRMA-QSA-BITS CT-FIRMA-QSA
           IF CT-RC NOT = ZERO
               PERFORM ERROR-FIRMA
           END-IF.
       CLAVE-SESION-BANCO.
           *--- Acuerdo de clave HIBRIDO X25519 + ML-KEM-768 (FIPS 203) ---
      *    (1) Componente clasico: X25519 via ICSF. CT-CLAVE y
      *        CT-PUBLICA deben ser tokens ECC de curva 25519
      *        (generados con CSNDPKB), NO curvas P-256/P-384.
           CALL 'CSNDEDH' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CUENTA-UNA CT-REGLAS-EDH
               CT-CLAVE-LARGO CT-CLAVE CT-CERO CT-AREA
               CT-CLAVE-LARGO CT-PUBLICA CT-CERO CT-AREA
               CT-CERO CT-AREA CT-BITS-DERIVADOS CT-CERO CT-AREA
           IF CT-RC NOT = ZERO
               PERFORM CT-ERROR-CRIPTO
           END-IF
           MOVE CT-SALIDA TO CT-SS-X25519
      *    (2) Componente post-cuantico: encapsulacion ML-KEM-768
      *        contra la clave publica ML-KEM del par (sustituye a
      *        CSNDPKE/RSA). Rutina 'PQCKEM' = wrapper Java que
      *        invoca Bouncy Castle 1.78 (provider BCPQC).
           MOVE 'ML-KEM-768' TO CT-KEM-ALG
           MOVE 'ENCAPS    ' TO CT-KEM-OPER
           CALL 'PQCKEM' USING CT-RC CT-RAZON
               CT-KEM-ALG CT-KEM-OPER
               CT-MLKEM-PUB-LARGO CT-MLKEM-PUB
               CT-KEM-CT-LARGO CT-KEM-CT
               CT-SS-MLKEM-LARGO CT-SS-MLKEM
           IF CT-RC NOT = ZERO
               PERFORM CT-ERROR-PQC
           END-IF
      *    (3) Combinacion de secretos: KDF SHA-256 sobre
      *        SS-X25519 || SS-MLKEM || CT-KEM (ICSF CSNBOWH).
      *        CT-KEM-CT se envia al par junto a la publica X25519.
           STRING CT-SS-X25519 DELIMITED BY SIZE
                  CT-SS-MLKEM  DELIMITED BY SIZE
                  CT-KEM-CT    DELIMITED BY SIZE
                  INTO CT-KDF-ENTRADA
           END-STRING
           MOVE 'SHA-256 ' TO CT-REGLAS-OWH(1)
           MOVE 'ONLY    ' TO CT-REGLAS-OWH(2)
           MOVE 2          TO CT-CUENTA-DOS
           CALL 'CSNBOWH' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CUENTA-DOS CT-REGLAS-OWH
               CT-KDF-ENTRADA-LARGO CT-KDF-ENTRADA
               CT-CERO CT-AREA CT-HASH-LARGO CT-CLAVE-SESION
           IF CT-RC NOT = ZERO
               PERFORM CT-ERROR-CRIPTO
           END-IF
      *    (4) Borrado del material intermedio en memoria
           MOVE LOW-VALUES TO CT-SS-X25519 CT-SS-MLKEM
                              CT-KDF-ENTRADA
               CT-CERO CT-AREA CT-CERO CT-AREA CT-CERO CT-AREA
               CT-CERO CT-AREA CT-CERO CT-AREA CT-CLAVE-LARGO
               CT-CLAVE.
