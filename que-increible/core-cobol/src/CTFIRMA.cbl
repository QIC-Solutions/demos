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
      *    CT-REGLAS-EDDSA  = 'EDDSA   ' 'MESSAGE '
      *    CT-REGLAS-MLDSA  = 'ML-DSA  ' 'MESSAGE '
      *    (CT-CLAVE-ED = token Ed25519, CT-CLAVE-MLDSA = token ML-DSA-65)
           CALL 'CSNDDSG' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CUENTA-DOS CT-REGLAS-EDDSA
               CT-CLAVE-ED-LARGO CT-CLAVE-ED CT-MSG-LARGO CT-MSG
               CT-FIRMA-ED-LARGO CT-FIRMA-ED-BITS CT-FIRMA-ED
           IF CT-RC NOT = ZERO
               PERFORM ERROR-FIRMA
           END-IF
           CALL 'CSNDDSG' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CUENTA-DOS CT-REGLAS-MLDSA
               CT-CLAVE-MLDSA-LARGO CT-CLAVE-MLDSA CT-MSG-LARGO CT-MSG
               CT-FIRMA-PQ-LARGO CT-FIRMA-PQ-BITS CT-FIRMA-PQ
           IF CT-RC NOT = ZERO
               PERFORM ERROR-FIRMA
           END-IF
      *    FIRMA COMPUESTA = FIRMA-ED || FIRMA-PQ (AMBAS SE VERIFICAN)
           STRING CT-FIRMA-ED DELIMITED BY SIZE
                  CT-FIRMA-PQ DELIMITED BY SIZE
                  INTO CT-FIRMA
           END-STRING.
       CLAVE-SESION-BANCO.
           *    Firma (sin cambios en este hallazgo)
           CALL 'CSNDPKE' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CUENTA-UNA CT-REGLAS-PKE
               CT-HASH-LARGO CT-HASH CT-CERO CT-AREA
               CT-CLAVE-LARGO CT-PUBLICA CT-FIRMA-LARGO CT-FIRMA
      *    Paso 1: componente clasico del hibrido (X25519 en ICSF)
           MOVE 'X25519  ' TO CT-REGLAS-EDH-CURVA
           CALL 'CSNDEDH' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CUENTA-DOS CT-REGLAS-EDH
               CT-CLAVE-LARGO CT-CLAVE CT-CERO CT-AREA
               CT-CLAVE-LARGO CT-PUBLICA CT-CERO CT-AREA
               CT-CERO CT-AREA CT-BITS-DERIVADOS CT-CERO CT-AREA
           IF CT-RC NOT = ZERO
               PERFORM 9000-ERROR-CRIPTO
           END-IF
           MOVE CT-SALIDA(1:32) TO CT-SECRETO-ECDH
      *    Paso 2: componente post-cuantico ML-KEM-768 (FIPS 203)
      *    QSMLKEM = stub que invoca Bouncy Castle 1.78 (BCPQC)
      *    Entrada: clave publica ML-KEM-768 del par (1184 bytes)
      *    Salida : ciphertext (1088 bytes) + secreto (32 bytes)
           CALL 'QSMLKEM' USING CT-RC CT-RAZON
               CT-MLKEM-REGLA
               CT-MLKEM-PUB-LARGO CT-MLKEM-PUB
               CT-MLKEM-CT-LARGO CT-MLKEM-CT
               CT-MLKEM-SS-LARGO CT-SECRETO-MLKEM
           IF CT-RC NOT = ZERO
               PERFORM 9000-ERROR-CRIPTO
           END-IF
      *    Paso 3: combinar ambos secretos con KDF (HKDF-SHA-256)
           MOVE CT-SECRETO-ECDH  TO CT-IKM(1:32)
           MOVE CT-SECRETO-MLKEM TO CT-IKM(33:32)
           MOVE 64 TO CT-IKM-LARGO
           MOVE 'X25519-MLKEM768-HKDF-SHA256' TO CT-KDF-INFO
           CALL 'QSHKDF' USING CT-RC CT-RAZON
               CT-IKM-LARGO CT-IKM
               CT-KDF-INFO-LARGO CT-KDF-INFO
               CT-BITS-DERIVADOS CT-CLAVE-SESION
           IF CT-RC NOT = ZERO
               PERFORM 9000-ERROR-CRIPTO
           END-IF
      *    Enviar CT-MLKEM-CT junto con la clave publica X25519 al par
      *    Borrar secretos intermedios de memoria
           MOVE LOW-VALUES TO CT-SECRETO-ECDH
                              CT-SECRETO-MLKEM CT-IKM
               CT-CERO CT-AREA CT-CERO CT-AREA CT-CERO CT-AREA
               CT-CERO CT-AREA CT-CERO CT-AREA CT-CLAVE-LARGO
               CT-CLAVE.
