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
      *    Sustituye el esqueleto RSA-2048 por un par QSA ML-KEM-768
      *    (FIPS 203). Rule array: 'QSA-PAIR' + 'KYBER   ' y la
      *    estructura CT-ESTRUCTURA-QSA parametrizada para ML-KEM-768.
           MOVE 2            TO CT-CUENTA-QSA
           MOVE 'QSA-PAIR'   TO CT-REGLA-QSA(1)
           MOVE 'KYBER   '   TO CT-REGLA-QSA(2)
           CALL 'CSNDPKB' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CUENTA-QSA CT-REGLA-QSA
               CT-QSA-LARGO CT-ESTRUCTURA-QSA CT-CERO CT-AREA
               CT-CERO CT-AREA CT-CERO CT-AREA CT-CERO CT-AREA
               CT-CERO CT-AREA CT-CERO CT-AREA
           IF CT-RC NOT = ZERO
               PERFORM ERROR-CRIPTO
           END-IF
      *    Componente clasico del esquema hibrido: X25519 (ECC-PAIR)
           MOVE 2            TO CT-CUENTA-ECC
           MOVE 'ECC-PAIR'   TO CT-REGLA-ECC(1)
           MOVE 'X25519  '   TO CT-REGLA-ECC(2)
           CALL 'CSNDPKB' USING CT-RC CT-RAZON CT-SALIDA-ECC-LARGO
               CT-SALIDA-ECC CT-CUENTA-ECC CT-REGLA-ECC
               CT-ECC-LARGO CT-ESTRUCTURA-ECC CT-CERO CT-AREA
               CT-CERO CT-AREA CT-CERO CT-AREA CT-CERO CT-AREA
               CT-CERO CT-AREA CT-CERO CT-AREA
           IF CT-RC NOT = ZERO
               PERFORM ERROR-CRIPTO
           END-IF
      *    En CLAVE-SESION-BANCO: encapsular con ML-KEM-768, acordar
      *    con X25519 y combinar ambos secretos via KDF (HKDF-SHA-256)
      *    para derivar la clave de sesion. Si el HSM no soporta
      *    ML-KEM, invocar el modulo Java PQC (Bouncy Castle, provider
      *    BCPQC) mediante CALL 'KEMMLKEM' USING CT-PUB-MLKEM
      *        CT-CIPHERTEXT CT-SECRETO-COMPARTIDO.
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
      *    Digest con SHA-256 (sustituye a SHA-1)
           MOVE 1               TO CT-CUENTA-UNO
           MOVE 'SHA-256 '      TO CT-REGLA-HASH
           MOVE 32              TO CT-HASH-LARGO
           CALL 'CSNBOWH' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CUENTA-UNO CT-REGLA-HASH
               CT-TEXTO-LARGO CT-TEXTO CT-ENCADENA-LARGO
               CT-ENCADENA CT-HASH-LARGO CT-HASH
           IF CT-RC NOT = 0
               PERFORM ERROR-CRIPTO
           END-IF
      *    Regla de firma: formato de hash SHA-256
           MOVE 'SHA-256 '      TO CT-REGLAS-FIRMA(2)
           CALL 'CSNDDSG' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CUENTA-CUATRO CT-REGLAS-FIRMA
               CT-CLAVE-LARGO CT-CLAVE CT-HASH-LARGO CT-HASH
               CT-FIRMA-LARGO CT-FIRMA-BITS CT-FIRMA
           IF CT-RC NOT = 0
               PERFORM ERROR-CRIPTO
           END-IF
               CT-SALIDA CT-CUENTA-TRES CT-REGLAS-ECDSA
               CT-CLAVE-LARGO CT-CLAVE CT-HASH-LARGO CT-HASH
               CT-FIRMA-LARGO CT-FIRMA-BITS CT-FIRMA.
       CLAVE-SESION-BANCO.
      *    Sustituye CSNDPKE (RSA) por encapsulacion hibrida
      *    X25519 + ML-KEM-768 (NIST FIPS 203) a traves de la
      *    rutina puente PQCENCAP implementada sobre
      *    Bouncy Castle 1.78 (provider BCPQC).
           MOVE 'ML-KEM-768 ' TO CT-REGLAS-KEM-ALG
           MOVE 'X25519     ' TO CT-REGLAS-KEM-ECDH
           MOVE 'HKDF-SHA256' TO CT-REGLAS-KEM-KDF
           MOVE 3            TO CT-CUENTA-TRES
           CALL 'PQCENCAP' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CUENTA-TRES CT-REGLAS-KEM
               CT-CLAVE-LARGO CT-PUBLICA-MLKEM
               CT-CLAVE-EC-LARGO CT-PUBLICA-X25519
               CT-CIFRADO-LARGO CT-CIFRADO-KEM
               CT-SECRETO-LARGO CT-SECRETO-COMBINADO
           IF CT-RC NOT = ZERO
               PERFORM ERROR-CRIPTO-PQC
           END-IF
      *    CT-SECRETO-COMBINADO es la clave de sesion derivada;
      *    CT-CIFRADO-KEM (ciphertext ML-KEM + clave efimera
      *    X25519) se envia al banco en lugar del bloque RSA.
           CALL 'CSNDEDH' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CUENTA-UNA CT-REGLAS-EDH
               CT-CLAVE-LARGO CT-CLAVE CT-CERO CT-AREA
               CT-CLAVE-LARGO CT-PUBLICA CT-CERO CT-AREA
               CT-CERO CT-AREA CT-BITS-DERIVADOS CT-CERO CT-AREA
               CT-CERO CT-AREA CT-CERO CT-AREA CT-CERO CT-AREA
               CT-CERO CT-AREA CT-CERO CT-AREA CT-CLAVE-LARGO
               CT-CLAVE.
