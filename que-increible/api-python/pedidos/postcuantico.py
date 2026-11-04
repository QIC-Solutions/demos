"""Piloto post-cuántico con el almacén logístico, con liboqs (oqs-python).

Los nombres de los algoritmos se leen de config/seguridad.yaml.
"""

import oqs
import yaml

with open("config/seguridad.yaml", encoding="utf-8") as fichero:
    _CONFIG = yaml.safe_load(fichero)["almacen"]


def encapsular_para_almacen(clave_publica_almacen: bytes) -> tuple[bytes, bytes]:
    with oqs.KeyEncapsulation(_CONFIG["kem"]) as kem:
        return kem.encap_secret(clave_publica_almacen)


def firmar_manifiesto(manifiesto: bytes) -> tuple[bytes, bytes]:
    with oqs.Signature("ML-DSA-65") as firmante:
        publica = firmante.generate_keypair()
        return publica, firmante.sign(manifiesto)
