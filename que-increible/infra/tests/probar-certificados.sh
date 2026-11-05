#!/bin/sh
# Prueba de los scripts de certificados: usa las MISMAS primitivas PQC que producción.
# Requiere OpenSSL 3.5+ (ML-KEM nativo) u OpenSSL 3.x con oqs-provider (añadir: -provider oqsprovider -provider default).
set -eu
# Par de claves ML-KEM-768 (FIPS 203)
openssl genpkey -algorithm mlkem768 -out /tmp/prueba_mlkem768.key
openssl pkey -in /tmp/prueba_mlkem768.key -pubout -out /tmp/prueba_mlkem768.pub
# Componente clásica del esquema híbrido X25519 + ML-KEM-768
openssl genpkey -algorithm X25519 -out /tmp/prueba_x25519.key
# Huella de verificación con SHA-256 en lugar de MD4
openssl dgst -sha256 /tmp/prueba_mlkem768.key
openssl dgst -sha256 /tmp/prueba_x25519.key
