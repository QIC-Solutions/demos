#!/bin/bash
# Acceso de operaciones a los TPV de tienda (demo). Los TPV de 2012 solo
# hablan los algoritmos viejos de SSH.
set -euo pipefail

# La generación automática no estuvo disponible. Aplicar la recomendación PQC indicada sobre el código detectado.

# El servidor de cobros heredado: TLS 1.0.
curl --tlsv1.0 --tls-max 1.0 https://cobros-antiguo.que-increible.example/salud
