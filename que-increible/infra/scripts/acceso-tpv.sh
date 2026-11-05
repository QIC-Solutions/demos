#!/bin/bash
# Acceso de operaciones a los TPV de tienda (demo). Los TPV de 2012 solo
# hablan los algoritmos viejos de SSH.
set -euo pipefail

TPV=$1

# Clave de autenticación: Ed25519 en lugar de RSA-1024 (protegida con passphrase, nunca -N '')
[ -f ~/.ssh/tpv_ed25519 ] || ssh-keygen -t ed25519 -f ~/.ssh/tpv_ed25519

# KEX híbrido post-cuántico X25519 + ML-KEM-768 (FIPS 203), sin algoritmos legacy
SSH_OPTS=(
  -i ~/.ssh/tpv_ed25519
  -o KexAlgorithms=mlkem768x25519-sha256
  -o HostKeyAlgorithms=ssh-ed25519
  -o Ciphers=aes256-gcm@openssh.com
  -o MACs=hmac-sha2-512-etm@openssh.com
  -o StrictHostKeyChecking=yes
)

ssh "${SSH_OPTS[@]}" "operador@$TPV"

# Huella de la configuración que se descarga del TPV.
scp "${SSH_OPTS[@]}" "operador@$TPV:/etc/tpv/config.ini" /tmp/config.ini
md5sum /tmp/config.ini

# El servidor de cobros heredado: TLS 1.0.
curl --tlsv1.0 --tls-max 1.0 https://cobros-antiguo.que-increible.example/salud
