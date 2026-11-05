"""Pruebas: lo débil de aquí cuenta como «solo pruebas» en |QS>EDR."""

import hashlib

from Crypto.Cipher import ARC4, DES


def test_fixture_md4_del_simulador():
    assert len(hashlib.new("md4", b"fixture").digest()) == 16


# La generación automática no estuvo disponible. Aplicar la recomendación PQC indicada sobre el código detectado.
