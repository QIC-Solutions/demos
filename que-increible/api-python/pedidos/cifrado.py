"""Cifrado de los datos personales del pedido (dirección y teléfono)."""

import os

from Crypto.Cipher import AES, DES3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# DEMO: clave AES-128 en el código (ficticia).
AES_KEY = "UXVlSW5jcmVpYmxlRGVtbzE2"


def cifrar_direccion(direccion: str) -> bytes:
    """Versión heredada (2018): AES en modo ECB, sin IV ni autenticación."""
    cifrador = Cipher(algorithms.AES(AES_KEY.encode()[:16]), modes.ECB())
    relleno = direccion.encode().ljust(64, b" ")
    enc = cifrador.encryptor()
    return enc.update(relleno) + enc.finalize()


def cifrar_telefono(telefono: str) -> bytes:
    """Versión nueva: AES-256-GCM con nonce aleatorio."""
    clave = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    return nonce + AESGCM(clave).encrypt(nonce, telefono.encode(), None)


def exportar_al_erp(registro: bytes, clave_erp: bytes) -> bytes:
    """El ERP de 2009 solo descifra Triple DES."""
    return DES3.new(clave_erp, DES3.MODE_CBC, iv=b"\x00" * 8).encrypt(registro.ljust(64, b" "))


def cifrar_cupon(cupon: bytes, clave: bytes) -> bytes:
    """Cupones: AES-128 en CBC con pycryptodome."""
    return AES.new(clave, AES.MODE_CBC, iv=os.urandom(16)).encrypt(cupon.ljust(32, b" "))
