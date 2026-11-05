       IDENTIFICATION DIVISION.
       PROGRAM-ID. CTCIFRA.
      *----------------------------------------------------------------
      * Que Increible Compania SL (empresa ficticia de demo).
      * Nucleo contable: cifrado de los ficheros de asientos que se
      * envian a la gestoria y al banco, con ICSF.
      * DEMO: la criptografia debil esta a proposito.
      *----------------------------------------------------------------
       ENVIRONMENT DIVISION.
       DATA DIVISION.
       WORKING-STORAGE SECTION.
           COPY CTCOMUN.
       01  CT-VECTOR               PIC X(16)     VALUE LOW-VALUES.
       01  CT-TEXTO-LARGO          PIC 9(8) COMP VALUE 256.
       01  CT-TEXTO                PIC X(256)    VALUE SPACES.
       01  CT-CIFRADO              PIC X(256)    VALUE SPACES.
      * Asientos del dia: AES-256 en CBC con relleno, clave en claro.
       01  CT-REGLAS-AES.
           05  FILLER              PIC X(8) VALUE 'AES     '.
           05  FILLER              PIC X(8) VALUE 'PKCS-PAD'.
           05  FILLER              PIC X(8) VALUE 'KEY-CLR '.
       01  CT-LARGO-AES            PIC 9(8) COMP VALUE 32.
      * DEMO: clave en claro escrita en el programa (ficticia).
       01  CT-CLAVE-CLARA          PIC X(32)
               VALUE 'QIC-DEMO-NO-REAL-CLAVE-CONTABLE!'.
      * Gestoria (2009): Triple DES en ECB.
       01  CT-REGLAS-TDES          PIC X(16) VALUE 'DES     ECB     '.
       01  CT-LARGO-TDES           PIC 9(8) COMP VALUE 24.
      * Banco: DES simple, clave de 8 bytes.
       01  CT-CLAVE-DES            PIC X(8)      VALUE 'DEMO8BYT'.
       PROCEDURE DIVISION.
       PRINCIPAL.
           PERFORM CIFRAR-ASIENTOS
           PERFORM CIFRAR-GESTORIA
           PERFORM CIFRAR-BANCO
           GOBACK.
       CIFRAR-ASIENTOS.
           CALL 'CSNBSYE' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CUENTA-TRES CT-REGLAS-AES CT-LARGO-AES
               CT-CLAVE-CLARA CT-CERO CT-AREA CT-CERO CT-CERO
               CT-VECTOR CT-CERO CT-AREA CT-TEXTO-LARGO CT-TEXTO
               CT-TEXTO-LARGO CT-CIFRADO CT-CERO CT-AREA.
       CIFRAR-GESTORIA.
      *    Reglas AES-256-GCM: 'AES     GCM     KEYIDENT' (3 reglas)
      *    Clave AES de 256 bits almacenada en el CKDS (etiqueta)
      *    IV de 12 bytes (96 bits) unico por mensaje
      *    AAD opcional en CT-AAD; etiqueta (16 bytes) en CT-TAG
           MOVE 3                  TO CT-CUENTA-TRES.
           MOVE 'AES     GCM     KEYIDENT' TO CT-REGLAS-AES.
           MOVE 64                 TO CT-LARGO-ETIQUETA.
           MOVE 16                 TO CT-BLOQUE.
           MOVE 12                 TO CT-VECTOR-LARGO.
           MOVE 16                 TO CT-TAG-LARGO.
           CALL 'CSNBSAE' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CUENTA-TRES CT-REGLAS-AES
               CT-LARGO-ETIQUETA CT-ETIQUETA-AES256
               CT-AAD-LARGO CT-AAD CT-BLOQUE
               CT-VECTOR-LARGO CT-VECTOR CT-CERO CT-AREA
               CT-TEXTO-LARGO CT-TEXTO
               CT-TEXTO-LARGO CT-CIFRADO CT-TAG-LARGO CT-TAG.
           IF CT-RC NOT = ZERO
               PERFORM ERROR-CIFRADO
           END-IF.
       CIFRAR-BANCO.
           CALL 'CSNBECO' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CLAVE-DES CT-TEXTO CT-CIFRADO.
