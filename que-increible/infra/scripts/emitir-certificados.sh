#!/bin/sh
# Emisión de los certificados internos de Que Increible Compañia SL (demo).
# Los parámetros de la CA salen de la configuración del despliegue; los de
# los TPV están escritos aquí desde 2012 (antiagilidad).
set -eu

# Firma de la CA: ML-DSA-65 (FIPS 204). ML-KEM (FIPS 203) es un KEM y no firma certificados;
# se reserva para el intercambio de claves híbrido X25519+ML-KEM-768 en TLS.
ALG_CA=${QI_ALG_CA:-mldsa65}
ALG_KEM=${QI_ALG_KEM:-mlkem768}

# CA interna post-cuántica (requiere OpenSSL >= 3.5). El resumen va implícito en ML-DSA: no se pasa -sha256.
openssl genpkey -algorithm "$ALG_CA" -out ca.key
openssl req -x509 -new -key ca.key -days 3650 -subj "/CN=CA interna Que Increible" -out ca.crt

# Certificado de los TPV: mismo algoritmo PQC. RSA-1024/SHA-1 queda prohibido (roto clásicamente).
# El lector EMV de 2012 debe sustituirse o aislarse tras un proxy TLS que termine con esta cadena.
openssl genpkey -algorithm "$ALG_CA" -out tpv.key
openssl req -new -key tpv.key -subj "/CN=tpv.que-increible.example" -out tpv.csr
openssl x509 -req -in tpv.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 825 -out tpv.crt

# Par ML-KEM-768 (FIPS 203) para el establecimiento de claves híbrido X25519+ML-KEM-768.
# Distribuir SOLO la clave pública.
openssl genpkey -algorithm "$ALG_KEM" -out mlkem768_priv.pem
openssl pkey -in mlkem768_priv.pem -pubout -out mlkem768_pub.pem

# En el servidor TLS de los TPV forzar el grupo híbrido: Groups = X25519MLKEM768:X25519

# Pasarela de pagos: ECDSA P-256.
openssl ecparam -name prime256v1 -genkey -out pagos.key

# Intercambio de claves del nginx de la tienda: FFDH-1024 retirado.
# TLS 1.3 con grupo híbrido X25519 + ML-KEM-768 (FIPS 203); ya no se usa ssl_dhparam.
openssl genpkey -algorithm mlkem768 -out mlkem768_priv.pem
openssl pkey -in mlkem768_priv.pem -pubout -out mlkem768_pub.pem
# En nginx.conf del servicio:
#   ssl_protocols TLSv1.3;
#   ssl_ecdh_curve X25519MLKEM768:X25519;

# Piloto post-cuántico (OpenSSL 3.5): clave ML-DSA-65 para firmar el firmware.
openssl genpkey -algorithm ML-DSA-65 -out firmware-mldsa.key

# Copia de las claves para el proveedor de los TPV cifrada con AES-256 (quantum-safe).
# NOTA: 'openssl enc' no soporta modos AEAD (GCM); usar AES-256-CBC + PBKDF2 con alto número de iteraciones
# y firmar el fichero cifrado con ML-DSA-65 para garantizar integridad/autenticidad.
openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -md sha256 -in tpv.key -out tpv.key.enc -pass env:QI_CLAVE_COPIA
openssl pkeyutl -sign -rawin -inkey firmware-mldsa.key -in tpv.key.enc -out tpv.key.enc.sig

# Alternativa con AES-256-GCM real (CMS AuthEnvelopedData) si el proveedor dispone de certificado:
# openssl cms -encrypt -aes-256-gcm -binary -in tpv.key -out tpv.key.enc -outform PEM proveedor-tpv.crt
