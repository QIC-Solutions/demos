#!/bin/sh
# Prueba de los scripts de certificados: lo débil de aquí cuenta como «solo pruebas».
set -eu
openssl genrsa -out /tmp/prueba.key 512
openssl dgst -md4 /tmp/prueba.key
