#!/bin/sh
# Emisión de los certificados internos de Que Increible Compañia SL (demo).
# Los parámetros de la CA salen de la configuración del despliegue; los de
# los TPV están escritos aquí desde 2012 (antiagilidad).
set -eu

BITS_CA=${QI_BITS_CA:-4096}
RESUMEN=${QI_RESUMEN:-sha256}

# CA interna: el tamaño y el resumen se eligen fuera del script.
openssl genrsa -out ca.key "$BITS_CA"
openssl req -x509 -new -key ca.key -"$RESUMEN" -days 3650 -subj "/CN=CA interna Que Increible" -out ca.crt

# Certificado de los TPV: RSA-1024 con SHA-1, porque el lector EMV de 2012 no admite más.
openssl req -new -newkey rsa:1024 -nodes -sha1 -keyout tpv.key -out tpv.csr -subj "/CN=tpv.que-increible.example"

# Pasarela de pagos: ECDSA P-256.
openssl ecparam -name prime256v1 -genkey -out pagos.key

# Parámetros DH del nginx de la tienda.
openssl dhparam -out dhparam-1024.pem 1024

# Piloto post-cuántico (OpenSSL 3.5): clave ML-DSA-65 para firmar el firmware.
openssl genpkey -algorithm ML-DSA-65 -out firmware-mldsa.key

# Copia de las claves en un zip cifrado con 3DES para el proveedor de los TPV.
openssl enc -des-ede3-cbc -pbkdf2 -in tpv.key -out tpv.key.enc -pass env:QI_CLAVE_COPIA
