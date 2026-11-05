#!/bin/bash
# Acceso de operaciones a los TPV de tienda (demo). Los TPV de 2012 solo
# hablan los algoritmos viejos de SSH.
set -euo pipefail

TPV=$1

# Clave de usuario: Ed25519 (se elimina RSA-1024). Rotar a ML-DSA cuando OpenSSH lo soporte.
ssh-keygen -t ed25519 -f ~/.ssh/tpv_ed25519 -N '' -C "operador@tpv"

# Intercambio de claves híbrido X25519 + ML-KEM-768 (FIPS 203). Requiere OpenSSH >= 9.9.
SSH_OPTS=(
  -o KexAlgorithms=mlkem768x25519-sha512,sntrup761x25519-sha512@openssh.com
  -o HostKeyAlgorithms=ssh-ed25519,sk-ssh-ed25519@openssh.com
  -o Ciphers=chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
  -o MACs=hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
  -o StrictHostKeyChecking=yes
  -i ~/.ssh/tpv_ed25519
)
ssh "${SSH_OPTS[@]}" "operador@$TPV"

# Huella de la configuración que se descarga del TPV.
scp "${SSH_OPTS[@]}" "operador@$TPV:/etc/tpv/config.ini" /tmp/config.ini
md5sum /tmp/config.ini

# El servidor de cobros heredado: TLS 1.0.
curl --tlsv1.0 --tls-max 1.0 https://cobros-antiguo.que-increible.example/salud
