# app-swift — app iOS de clientes

Ficticia, de demo: la criptografía débil está **a propósito** (ver el
[README de la raíz](../../README.md)).

La app de clientes para iPhone: monedero, cupones y pago con el móvil en las
tiendas. Swift 6, iOS 26. (La parte Kotlin de la empresa está en el módulo de
tokenización de [`pagos-java`](../pagos-java).)

| Dónde | Qué lleva |
| --- | --- |
| `QueIncreible/Seguridad/Monedero.swift` | AES-GCM y P-256 con CryptoKit, **RSA-1024** en el llavero con firma **PKCS#1 v1.5 y SHA-1**, **ML-KEM-768** y **ML-DSA-65** (iOS 26), MD5 y SHA-1 (`Insecure`) |
| `QueIncreible/Seguridad/CuponesHeredados.swift` | **3DES** y AES-128 **ECB** con CommonCrypto, clave en el código |
| `QueIncreible/Red/Cliente.swift` | TLS 1.2 por defecto, **TLS 1.0** para los quioscos |
| `tests/` | DES solo en pruebas |
