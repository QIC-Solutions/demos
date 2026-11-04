# gateway-go — pasarela API interna

Ficticia, de demo: la criptografía débil está **a propósito** (ver el
[README de la raíz](../../README.md)).

La pasarela que recibe el tráfico de la tienda, el portal y la app y lo reparte
a los servicios internos. Go 1.24.

| Dónde | Qué lleva |
| --- | --- |
| `internal/tlsconf/tls.go` | Servidor TLS 1.2+ con el grupo híbrido **X25519MLKEM768**; cliente de facturación en **TLS 1.0-1.1** con suites 3DES y RC4 |
| `internal/firma/firma.go` | RSA-2048, **RSA-1024**, PKCS#1 v1.5 con **SHA-1**, RSA-PSS y ECDSA P-256 |
| `internal/sesion/jwt.go` | JWT HS256 y HMAC-SHA-256 con secretos en el código, MD5 para la caché |
| `internal/pqc/mlkem.go` | **ML-KEM-768** con `crypto/mlkem`, junto al ECDH P-256 de antes |
| `internal/cifrado/` | AES-GCM y **3DES**; DES, RC4 y MD5 solo en pruebas |
