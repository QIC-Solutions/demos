#!/bin/sh
# Emisión de los certificados internos de Que Increible Compañia SL (demo).
# Los parámetros de la CA salen de la configuración del despliegue; los de
# los TPV están escritos aquí desde 2012 (antiagilidad).
set -eu

# La generación automática no estuvo disponible. Aplicar la recomendación PQC indicada sobre el código detectado.

# La generación automática no estuvo disponible. Aplicar la recomendación PQC indicada sobre el código detectado.

# Copia de las claves en un zip cifrado con 3DES para el proveedor de los TPV.
openssl enc -des-ede3-cbc -pbkdf2 -in tpv.key -out tpv.key.enc -pass env:QI_CLAVE_COPIA
