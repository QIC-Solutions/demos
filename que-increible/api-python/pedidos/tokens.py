"""Tokens de sesión de los clientes (JWT)."""

import os

import jwt

# DEMO — criptografía incrustada: el secreto HS256 está en el código (ficticio).
JWT_SECRET = "que-increible-api-pedidos-secreto-de-demo"


def emitir(usuario: str) -> str:
    # Algoritmo fijo en la llamada: HS256 con el secreto de arriba.
    return jwt.encode({"sub": usuario}, JWT_SECRET, algorithm="HS256")


def validar(token: str) -> str | None:
    try:
        datos = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    return datos.get("sub")


def emitir_para_socios(usuario: str, clave_privada: bytes) -> str:
    # La versión ágil: el algoritmo sale del entorno (ES256 hoy, ML-DSA mañana).
    return jwt.encode({"sub": usuario}, clave_privada, algorithm=os.environ["PEDIDOS_JWT_ALG"])
