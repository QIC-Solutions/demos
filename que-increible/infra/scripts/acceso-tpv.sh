#!/bin/bash
# Acceso de operaciones a los TPV de tienda (demo). Los TPV de 2012 solo
# hablan los algoritmos viejos de SSH.
set -euo pipefail

TPV=$1

ssh-keygen -t rsa -b 1024 -f ~/.ssh/tpv_rsa -N ''
ssh -o KexAlgorithms=+diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa -c 3des-cbc "operador@$TPV"

# Huella de la configuración que se descarga del TPV.
scp "operador@$TPV:/etc/tpv/config.ini" /tmp/config.ini
md5sum /tmp/config.ini

# El servidor de cobros heredado: TLS 1.0.
curl --tlsv1.0 --tls-max 1.0 https://cobros-antiguo.que-increible.example/salud
