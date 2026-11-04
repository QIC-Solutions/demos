# pagos-java — pasarela de pagos

Ficticia, de demo: la criptografía débil está **a propósito** (ver el
[README de la raíz](../../README.md)).

La pasarela de pagos de Que Increible Compañia SL cobra con tarjeta en la
tienda online y en las tiendas físicas. Es el sistema del proceso **«Cobros con
tarjeta»**, de criticidad **CROWN**: si cae o se compromete, la empresa no cobra.
Java 21 con Maven, y un módulo Kotlin para la tokenización de tarjetas.

| Dónde | Qué lleva |
| --- | --- |
| `cifrado/CifradoTarjetas.java` | El PAN en AES-128 **ECB** con la clave en el código; la versión nueva, AES-256-GCM |
| `cifrado/BloquePin.java` | Bloque de PIN en **3DES** y **DES** simple para los TPV antiguos |
| `firma/FirmaOrdenes.java` | Órdenes de cobro con RSA-2048 y RSA-1024, firma **SHA1withRSA**, recibos ECDSA P-256. Todo con el algoritmo escrito en la llamada |
| `firma/FirmaConfigurable.java` | La alternativa ágil: algoritmo y tamaño desde variables de entorno |
| `firma/AcuerdoClaves.java` | ECDH y Diffie-Hellman |
| `tls/ClienteAdquirente.java` | **TLS 1.0** y 1.1 con el banco adquirente, suites 3DES y RC4 |
| `huellas/HuellaTransaccion.java` | MD5, SHA-1 y un HMAC-SHA-256 con el secreto en el código |
| `claves/ClaveFirmaComercios.java` | Una clave privada PEM y un secreto JWT incrustados (ficticios) |
| `pqc/CanalPostCuantico.java` | Piloto post-cuántico: **ML-KEM-768** y **ML-DSA-65** con Bouncy Castle |
| `kotlin/.../Tokenizador.kt` | Token con SHA-1, bóveda AES-256-GCM, clave EC P-256, RSA con PKCS#1 v1.5 |
| `src/test/` | MD2 y RC4 solo en pruebas |
