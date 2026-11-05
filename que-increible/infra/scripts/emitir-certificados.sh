#!/bin/sh
# Emisión de los certificados internos de Que Increible Compañia SL (demo).
# Los parámetros de la CA salen de la configuración del despliegue; los de
# los TPV están escritos aquí desde 2012 (antiagilidad).
set -eu

ALG_CA=${QI_ALG_CA:-ML-DSA-65}

# CA interna: firma post-cuántica ML-DSA-65 (FIPS 204). ML-DSA no usa resumen externo (-sha256);
# el algoritmo se elige fuera del script. Requiere OpenSSL 3.5+ (o 3.x con oqs-provider).
openssl genpkey -algorithm "$ALG_CA" -out ca.key
openssl req -x509 -new -key ca.key -days 3650 -subj "/CN=CA interna Que Increible" -out ca.crt

# Certificado de los TPV: RSA-1024/SHA-1 está roto clásicamente; el lector EMV de 2012 debe
# sustituirse o aislarse en un segmento de red sin exposición. Emitimos con ML-DSA-65.
openssl genpkey -algorithm ML-DSA-65 -out tpv.key
openssl req -new -key tpv.key -subj "/CN=tpv.que-increible.example" -out tpv.csr

# El canal TLS que use estos certificados debe negociar KEM híbrido X25519 + ML-KEM-768 (FIPS 203):
#   openssl.cnf -> [ssl_sect] Groups = X25519MLKEM768:X25519
# o en el servidor: openssl s_server -cert tpv.crt -key tpv.key -groups X25519MLKEM768:X25519

# Pasarela de pagos: ECDSA P-256.
openssl ecparam -name prime256v1 -genkey -out pagos.key

# Intercambio de claves del nginx de la tienda: se elimina FFDH-1024 (vulnerable a Shor y Logjam).
# TLS 1.3 con grupo híbrido X25519 + ML-KEM-768 (FIPS 203); no se necesita dhparam.
# nginx: ssl_protocols TLSv1.3; ssl_ecdh_curve X25519MLKEM768:X25519;
openssl genpkey -algorithm mlkem768 -out tienda-mlkem768.key
openssl pkey -in tienda-mlkem768.key -pubout -out tienda-mlkem768.pub

# Piloto post-cuántico (OpenSSL 3.5): clave ML-DSA-65 para firmar el firmware.
openssl genpkey -algorithm ML-DSA-65 -out firmware-mldsa.key

# Copia de las claves cifrada con AES-256-GCM (autenticado) para el proveedor de los TPV.
# NOTA: 'openssl enc' no soporta modos AEAD (GCM); se usa 'openssl cms' con contraseña (PWRI).
openssl cms -encrypt -binary -aes-256-gcm \
  -pwri_password "$QI_CLAVE_COPIA" \
  -in tpv.key -outform DER -out tpv.key.enc

# Descifrado en el lado del proveedor:
# openssl cms -decrypt -inform DER -pwri_password "$QI_CLAVE_COPIA" -in tpv.key.enc -out tpv.key
