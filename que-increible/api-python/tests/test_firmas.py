"""Pruebas: lo débil de aquí cuenta como «solo pruebas» en |QS>EDR."""

import hashlib

from Crypto.Cipher import ARC4, DES


def test_fixture_md4_del_simulador():
    assert len(hashlib.new("md4", b"fixture").digest()) == 16


def test_cifrado_des_de_juguete():
    clave = b"8bytes!!"
    assert len(DES.new(clave, DES.MODE_ECB).encrypt(b"12345678")) == 8


def test_rc4_del_terminal_antiguo():
    assert ARC4.new(b"clave-de-prueba").encrypt(b"hola")
