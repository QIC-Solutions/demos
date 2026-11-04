"""Firmas de los albaranes y huellas de los pedidos."""

import hashlib
import hmac
import os
import ssl

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

# Secreto de las notificaciones al almacén (ficticio).
HMAC_SECRET = "almacen-que-increible-demo-0001"


def huella_pedido(datos: bytes) -> str:
    """Huella para deduplicar pedidos repetidos: MD5 (heredado)."""
    return hashlib.md5(datos).hexdigest()


def id_de_carrito(datos: bytes) -> str:
    return hashlib.sha1(datos).hexdigest()


def firmar_notificacion(cuerpo: bytes) -> str:
    return hmac.new(HMAC_SECRET.encode(), cuerpo, hashlib.sha256).hexdigest()


def clave_albaranes():
    """Par RSA-3072 para firmar los albaranes."""
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def clave_transportista_antiguo():
    """El transportista de 2010 solo valida RSA-1024."""
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


def firmar_albaran(clave, albaran: bytes) -> bytes:
    return clave.sign(albaran, padding.PKCS1v15(), hashes.SHA1())


def firmar_albaran_pss(clave, albaran: bytes) -> bytes:
    return clave.sign(
        albaran,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def clave_de_tienda():
    """Clave ECDSA P-256 de cada tienda física."""
    return ec.generate_private_key(ec.SECP256R1())


def secreto_con_tienda(propia, ajena) -> bytes:
    return propia.exchange(ec.ECDH(), ajena)


def contexto_almacen() -> ssl.SSLContext:
    """El almacén logístico aún negocia TLS 1.0."""
    return ssl.SSLContext(ssl.PROTOCOL_TLSv1)


def huella_auditoria(datos: bytes) -> str:
    """La versión ágil: el resumen de la auditoría se elige en el despliegue."""
    return hashlib.new(os.environ["PEDIDOS_RESUMEN_AUDITORIA"], datos).hexdigest()
