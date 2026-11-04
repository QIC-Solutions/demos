# firmware-c — firmware de los TPV de tienda

Ficticio, de demo: la criptografía débil está **a propósito** (ver el
[README de la raíz](../../README.md)).

El firmware de los terminales de punto de venta de las tiendas: el núcleo en C
(OpenSSL 3, mbedTLS y liboqs) y la interfaz en C++ (Crypto++ heredado y Botan 3).

| Dónde | Qué lleva |
| --- | --- |
| `src/terminal/pin.c` | Bloque de PIN en **3DES** y **DES** (mbedTLS), registro en AES-128 **ECB**, MD5, clave de transporte en el código |
| `src/terminal/tls_central.c` | `TLSv1_method()` con suites 3DES y RC4; el servidor nuevo, TLS 1.3 con **X25519MLKEM768** |
| `src/terminal/firma_tickets.c` | RSA-1024 (el tamaño, de `include/tpv_config.h`), firma con **SHA-1**, ECDSA P-256, RSA-2048 |
| `src/terminal/actualizacion.c` | Actualizaciones firmadas con **ML-DSA-65** y sesión con **ML-KEM-768** (liboqs) |
| `src/interfaz/Telemetria.cpp` | AES-128 **ECB** y MD5 con Crypto++; ML-DSA-65 con Botan 3 |
| `src/interfaz/Fidelizacion.cpp` | ECDSA P-256, RSA-3072 con **PKCS#1 v1.5 y SHA-1**, AES-256-GCM, SHA-1 |
| `tests/` | MD4 y RC4 solo en pruebas |
