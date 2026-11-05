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
               *    Reglas AES-256-GCM con clave protegida en CKDS (KEYIDENT)
       01  CT-CUENTA-TRES          PIC 9(9) COMP VALUE 3.
       01  CT-REGLAS-AES.
           05  FILLER              PIC X(8) VALUE 'AES     '.
           05  FILLER              PIC X(8) VALUE 'GCM     '.
           05  FILLER              PIC X(8) VALUE 'KEYIDENT'.
       01  CT-LARGO-ETIQUETA       PIC 9(9) COMP VALUE 64.
       01  CT-ETIQUETA-AES         PIC X(64)
           VALUE 'GESTORIA.AES256.GCM.2024'.
       01  CT-LARGO-TAG            PIC 9(9) COMP VALUE 16.
       01  CT-TAG-GCM              PIC X(16).
       01  CT-BLOQUE-AES           PIC 9(9) COMP VALUE 16.
       01  CT-LARGO-IV             PIC 9(9) COMP VALUE 12.
       01  CT-VECTOR-GCM           PIC X(12).
       01  CT-LARGO-AAD            PIC 9(9) COMP VALUE 0.
       01  CT-AAD                  PIC X(1).

       CIFRAR-GESTORIA.
      *    IV unico de 96 bits por operacion (nunca reutilizar)
           CALL 'CSNBRNGL' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CUENTA-UNO CT-REGLA-RANDOM
               CT-CERO CT-AREA CT-LARGO-IV CT-VECTOR-GCM.
           CALL 'CSNBSYE' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CUENTA-TRES CT-REGLAS-AES
               CT-LARGO-ETIQUETA CT-ETIQUETA-AES
               CT-LARGO-TAG CT-TAG-GCM CT-BLOQUE-AES
               CT-LARGO-IV CT-VECTOR-GCM CT-CERO CT-AREA
               CT-TEXTO-LARGO CT-TEXTO
               CT-TEXTO-LARGO CT-CIFRADO CT-LARGO-AAD CT-AAD.
      *    Persistir CT-VECTOR-GCM y CT-TAG-GCM junto al cifrado
       CIFRAR-BANCO.
           CALL 'CSNBECO' USING CT-RC CT-RAZON CT-SALIDA-LARGO
               CT-SALIDA CT-CLAVE-DES CT-TEXTO CT-CIFRADO.
