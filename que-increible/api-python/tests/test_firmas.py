"""Pruebas: lo débil de aquí cuenta como «solo pruebas» en |QS>EDR."""

import hashlib

from Crypto.Cipher import ARC4, DES


def test_fixture_md4_del_simulador():
    assert len(hashlib.new("md4", b"fixture").digest()) == 16


from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def test_cifrado_aes_256_gcm_de_juguete():
    clave = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    aesgcm = AESGCM(clave)
    texto_cifrado = aesgcm.encrypt(nonce, b"12345678", None)
    # 8 bytes de texto + 16 bytes de tag GCM
    assert len(texto_cifrado) == 8 + 16
    assert aesgcm.decrypt(nonce, texto_cifrado, None) == b"12345678"


def test_rc4_del_terminal_antiguo():
    # TODO: RC4 es un hallazgo independiente (ARC4); migrar también a AESGCM
    assert ARC4.new(b"clave-de-prueba").encrypt(b"hola")
