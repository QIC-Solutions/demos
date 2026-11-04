# core-cobol — núcleo contable en mainframe

Ficticio, de demo: la criptografía débil está **a propósito** (ver el
[README de la raíz](../../README.md)).

El núcleo contable de la empresa, en COBOL sobre z/OS, con los servicios
criptográficos de ICSF (CCA). La cadena nocturna está en `jcl/CTNOCHE.jcl`.

| Dónde | Qué lleva |
| --- | --- |
| `src/CTCIFRA.cbl` | Asientos en AES-256-CBC (`CSNBSYE`) con la clave en claro en el programa; gestoría en **3DES-ECB**; banco en **DES** (`CSNBECO`) |
| `src/CTFIRMA.cbl` | Claves RSA-2048 y EC P-256 (`CSNDPKB`), piloto **ML-DSA (6,5)** con QSA, cierre firmado con **PKCS#1 v1.5 y SHA-1** y con ECDSA (`CSNDDSG`), clave de sesión RSA (`CSNDPKE`) y ECDH (`CSNDEDH`) |
| `src/CTHASH.cbl` | **MD5**, SHA-1 y SHA-256 (`CSNBOWH`), HMAC-SHA-256 (`CSNBHMG`) |
| `tests/` | RIPEMD-160 solo en pruebas |

Los rule arrays van en `VALUE`: el algoritmo está escrito en el programa.
