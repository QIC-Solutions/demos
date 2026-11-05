#!/bin/sh
# Prueba de los scripts de certificados: las pruebas usan el MISMO material PQC que producción.
# Nada «débil solo para pruebas»: lo que se valida aquí es lo que se despliega.
set -eu
umask 077

# Híbrido X25519 + ML-KEM-768 (FIPS 203). Requiere OpenSSL 3.5+ (o 3.x con oqs-provider).
openssl genpkey -algorithm mlkem768 -out /tmp/prueba_mlkem768.key
openssl pkey -in /tmp/prueba_mlkem768.key -pubout -out /tmp/prueba_mlkem768.pub
openssl genpkey -algorithm X25519 -out /tmp/prueba_x25519.key
openssl pkey -in /tmp/prueba_x25519.key -pubout -out /tmp/prueba_x25519.pub

# Comprobar que la encapsulación/decapsulación ML-KEM-768 funciona de extremo a extremo
openssl pkeyutl -encap -inkey /tmp/prueba_mlkem768.pub -pubin -secret /tmp/ss_enc.bin -out /tmp/ct.bin
openssl pkeyutl -decap -inkey /tmp/prueba_mlkem768.key -in /tmp/ct.bin -secret /tmp/ss_dec.bin
cmp /tmp/ss_enc.bin /tmp/ss_dec.bin

# Huella de la clave PÚBLICA con SHA-256 (MD4 está roto; nunca hashear/mostrar la clave privada)
openssl dgst -sha256 /tmp/prueba_mlkem768.pub
openssl dgst -sha256 /tmp/prueba_x25519.pub

# Limpieza de secretos temporales
rm -f /tmp/ss_enc.bin /tmp/ss_dec.bin /tmp/ct.bin
