# infra — infraestructura y despliegue

Ficticia, de demo: la criptografía débil y las credenciales en claro están
**a propósito** (ver el [README de la raíz](../../README.md)).

| Dónde | Qué lleva |
| --- | --- |
| `nginx/tienda.conf` | La tienda con **TLSv1 y 1.1**, suites 3DES y RC4 y DH de 1024 bits; el portal, solo TLS 1.3 con **X25519MLKEM768** |
| `ssh/sshd_config` | Bastión con `diffie-hellman-group1-sha1`, `3des-cbc`, `arcfour`, `hmac-md5`, `ssh-rsa` y `ssh-dss`, junto a `mlkem768x25519-sha256` |
| `scripts/emitir-certificados.sh` | CA con tamaño y resumen desde el entorno; TPV con `openssl req -newkey rsa:1024 -sha1`; ECDSA P-256, DH-1024, **ML-DSA-65** con OpenSSL 3.5, copia en 3DES |
| `scripts/acceso-tpv.sh` | `ssh-keygen -b 1024`, SSH con DH group1 y 3DES, MD5, `curl --tlsv1.0` |
| `Dockerfile`, `Makefile` | Certificado RSA-2048, `wget --no-check-certificate`, `genrsa` de 1024 bits, SHA-1 |
| `docker-compose.yml` | Clave de cifrado, secreto JWT y contraseñas en claro (ficticios) |
| `certs/tienda-privada.pem`, `certs/tienda.crt` | Clave privada RSA-1024 y certificado autofirmado con SHA-1, **generados solo para la demo** |
| `tests/` | RSA-512 y MD4 solo en pruebas |
