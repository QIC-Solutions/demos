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
    """Huella para deduplicar pedidos repetidos: SHA-256 (migrado desde MD5)."""
    return hashlib.sha256(datos).hexdigest()


def id_de_carrito(datos: bytes) -> str:
    return hashlib.sha256(datos).hexdigest()


def firmar_notificacion(cuerpo: bytes) -> str:
    return hmac.new(HMAC_SECRET.encode(), cuerpo, hashlib.sha256).hexdigest()


import oqs


def clave_albaranes():
    """Par ML-DSA-65 (FIPS 204) para firmar los albaranes.

    Devuelve el objeto Signature (conserva la clave secreta en memoria)
    y la clave pública serializada para distribuirla.
    """
    firmante = oqs.Signature("ML-DSA-65")
    clave_publica = firmante.generate_keypair()
    return firmante, clave_publica


def clave_intercambio_albaranes():
    """Par ML-KEM-768 (FIPS 203) para cifrar/encapsular secretos de albaranes.

    Usar en híbrido X25519 + ML-KEM-768 combinando ambos secretos vía KDF.
    """
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    clave_publica = kem.generate_keypair()
    return kem, clave_publica


def clave_transportista_antiguo():
    """RSA-1024 está roto y no es quantum-safe: NO generar claves.

    Exigir al transportista la migración a ML-DSA-65 / X25519+ML-KEM-768.
    """
    raise NotImplementedError(
        "RSA-1024 deshabilitado: el transportista debe migrar a ML-DSA-65"
    )
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def firmar_albaran(clave, albaran: bytes) -> bytes:
    return clave.sign(albaran, padding.PKCS1v15(), hashes.SHA256())


import oqs
from cryptography.hazmat.primitives.asymmetric import ed25519


def firmar_albaran_hibrido(clave_ed25519: ed25519.Ed25519PrivateKey, clave_mldsa_secreta: bytes, albaran: bytes) -> bytes:
    # Firma híbrida: Ed25519 (clásica) + ML-DSA-65 (post-cuántica, FIPS 204). Ambas deben verificarse.
    firma_ed25519 = clave_ed25519.sign(albaran)
    with oqs.Signature("ML-DSA-65", clave_mldsa_secreta) as firmante:
        firma_mldsa = firmante.sign(albaran)
    return len(firma_ed25519).to_bytes(2, "big") + firma_ed25519 + firma_mldsa


def verificar_albaran_hibrido(pub_ed25519: ed25519.Ed25519PublicKey, pub_mldsa: bytes, albaran: bytes, firma: bytes) -> bool:
    longitud = int.from_bytes(firma[:2], "big")
    firma_ed25519 = firma[2:2 + longitud]
    firma_mldsa = firma[2 + longitud:]
    try:
        pub_ed25519.verify(firma_ed25519, albaran)
    except Exception:
        return False
    with oqs.Signature("ML-DSA-65") as verificador:
        return verificador.verify(albaran, firma_mldsa, pub_mldsa)


import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEM_ALG = "ML-KEM-768"  # NIST FIPS 203


def clave_de_tienda():
    """Par de claves híbrido X25519 + ML-KEM-768 de cada tienda física."""
    kem = oqs.KeyEncapsulation(KEM_ALG)
    kem_pub = kem.generate_keypair()
    ecdh_priv = x25519.X25519PrivateKey.generate()
    return {
        "kem": kem,
        "kem_pub": kem_pub,
        "ecdh_priv": ecdh_priv,
        "ecdh_pub": ecdh_priv.public_key(),
    }


def _combinar(ss_ecdh: bytes, ss_kem: bytes) -> bytes:
    """Combina ambos secretos (híbrido) en una clave de 32 bytes."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pedidos-tienda-x25519-mlkem768",
    ).derive(ss_ecdh + ss_kem)


def encapsular_con_tienda(propia, ajena_kem_pub: bytes, ajena_ecdh_pub) -> tuple[bytes, bytes]:
    """Lado iniciador: devuelve (ciphertext_kem, secreto_compartido)."""
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        ct, ss_kem = kem.encap_secret(ajena_kem_pub)
    ss_ecdh = propia["ecdh_priv"].exchange(ajena_ecdh_pub)
    return ct, _combinar(ss_ecdh, ss_kem)


def secreto_con_tienda(propia, ct: bytes, ajena_ecdh_pub) -> bytes:
    """Lado receptor: recupera el mismo secreto compartido a partir del ciphertext."""
    ss_kem = propia["kem"].decap_secret(ct)
    ss_ecdh = propia["ecdh_priv"].exchange(ajena_ecdh_pub)
    return _combinar(ss_ecdh, ss_kem)


def contexto_almacen() -> ssl.SSLContext:
    """El almacén logístico aún negocia TLS 1.0."""
    return ssl.SSLContext(ssl.PROTOCOL_TLSv1)


def huella_auditoria(datos: bytes) -> str:
    """La versión ágil: el resumen de la auditoría se elige en el despliegue."""
    return hashlib.new(os.environ["PEDIDOS_RESUMEN_AUDITORIA"], datos).hexdigest()
