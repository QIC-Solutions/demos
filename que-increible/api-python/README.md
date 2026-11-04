# api-python — API de pedidos

Ficticia, de demo: la criptografía débil está **a propósito** (ver el
[README de la raíz](../../README.md)).

La API de pedidos de la tienda online y de la app, en FastAPI.

| Dónde | Qué lleva |
| --- | --- |
| `pedidos/tokens.py` | JWT HS256 con el secreto en el código; la versión para socios lee el algoritmo del entorno |
| `pedidos/cifrado.py` | Direcciones en AES **ECB** con la clave en el código, teléfonos en AES-256-GCM, **3DES** para el ERP, AES-CBC con pycryptodome |
| `pedidos/firmas.py` | MD5 y SHA-1, HMAC con el secreto en el código, RSA-3072 y **RSA-1024**, firma PKCS#1 v1.5 con **SHA-1**, RSA-PSS, ECDSA P-256, ECDH, **TLS 1.0** con el almacén y un resumen configurable |
| `pedidos/postcuantico.py` | Piloto con liboqs: ML-KEM-768 y ML-DSA-65 (los nombres, en `config/seguridad.yaml`) |
| `tests/` | MD4, DES y RC4 solo en pruebas |
