# motor-rust — motor de conciliación bancaria

Ficticio, de demo: la criptografía débil está **a propósito** (ver el
[README de la raíz](../../README.md)).

Cada noche cruza los extractos del banco con los cobros de la pasarela y los
pagos a proveedores, y manda el informe a contabilidad. Rust 2021 con los
crates de RustCrypto y OpenSSL.

| Dónde | Qué lleva |
| --- | --- |
| `src/extractos.rs` | MD5 y SHA-1 para las huellas, AES-128 **ECB**, **3DES** para las devoluciones, AES-256-GCM para el archivo, clave en el código |
| `src/firma.rs` | RSA-2048 y **RSA-1024** con el tamaño en la llamada, uno con el tamaño desde el entorno, PKCS#1 v1.5 con SHA-256, ECDSA P-256 y **ML-KEM-768** |
| `src/canal.rs` | OpenSSL con **TLS 1.0** y suites 3DES, HMAC-SHA-1 y JWT HS256 con el secreto en el código |
| `tests/` | DES y RC4 solo en pruebas |
