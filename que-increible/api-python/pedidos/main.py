"""Punto de entrada de la API de pedidos (FastAPI)."""

from fastapi import FastAPI, Header, HTTPException

from pedidos import firmas, tokens
from pedidos.cifrado import cifrar_direccion

app = FastAPI(title="API de pedidos", version="2.7.0")


@app.post("/pedidos")
def crear_pedido(pedido: dict, authorization: str = Header(...)) -> dict:
    usuario = tokens.validar(authorization.removeprefix("Bearer "))
    if usuario is None:
        raise HTTPException(status_code=401)
    pedido["direccion"] = cifrar_direccion(pedido["direccion"]).hex()
    pedido["huella"] = firmas.huella_pedido(repr(pedido).encode())
    return {"ok": True, "pedido": pedido}
