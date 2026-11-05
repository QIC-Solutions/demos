"""Pruebas: lo débil de aquí cuenta como «solo pruebas» en |QS>EDR."""

import hashlib

from Crypto.Cipher import ARC4, DES


def test_fixture_md4_del_simulador():
    assert len(hashlib.new("md4", b"fixture").digest()) == 16


import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def test_cifrado_aes_256_gcm():
    clave = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)  # nonce único de 96 bits por cada cifrado
    aesgcm = AESGCM(clave)
    texto_cifrado = aesgcm.encrypt(nonce, b"12345678", None)
    assert len(texto_cifrado) == 8 + 16  # datos + etiqueta de autenticación GCM
    assert aesgcm.decrypt(nonce, texto_cifrado, None) == b"12345678"


def test_cifrado_autenticado_del_terminal():
    # RC4 (ARC4) también está roto y retirado; se sustituye por AES-256-GCM
    clave = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    assert AESGCM(clave).encrypt(nonce, b"hola", None)
