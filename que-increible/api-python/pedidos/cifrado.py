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


import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def exportar_al_erp(registro: bytes, clave_erp: bytes) -> bytes:
    """Exportación al ERP con AES-256-GCM (3DES retirado por NIST).
    El ERP debe actualizarse o recibir el registro a través de un adaptador
    que soporte AES-256-GCM. Devuelve nonce (12 bytes) || texto cifrado + tag."""
    if len(clave_erp) != 32:
        raise ValueError("clave_erp debe ser de 256 bits (32 bytes)")
    nonce = os.urandom(12)
    return nonce + AESGCM(clave_erp).encrypt(nonce, registro, associated_data=b"erp-export")


def cifrar_cupon(cupon: bytes, clave: bytes) -> bytes:
    """Cupones: AES-128 en CBC con pycryptodome."""
    return AES.new(clave, AES.MODE_CBC, iv=os.urandom(16)).encrypt(cupon.ljust(32, b" "))
