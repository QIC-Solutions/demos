# widget-js — widget de pago

Ficticia, de demo: la criptografía débil está **a propósito** (ver el
[README de la raíz](../../README.md)).

El widget de pago que las tiendas asociadas incrustan en su web, y su servidor,
en JavaScript (Node.js 22, sin TypeScript: es de antes del portal).

| Dónde | Qué lleva |
| --- | --- |
| `src/servidor.js` | El servidor HTTPS del widget, con **TLS 1.0** como mínimo por las tiendas con navegadores viejos, y la conexión con el adquirente antiguo en TLS 1.0 con **3DES** y **RC4** |
| `src/tokens.js` | Tokens de tarjeta en **3DES**, su huella en **MD5**, un HMAC-SHA-1 con el secreto en el código y la firma de los recibos con **RSA-1024** y **SHA-1**; los nuevos, en AES-256-GCM |
| `src/navegador.js` | Lo que corre en el navegador de la tienda: CryptoJS con AES derivado de una frase, **HMAC-SHA-1** y **MD5** |
| `src/futuro.js` | Lo ya post-cuántico: ML-KEM-768 de `node:crypto` y X25519 para el sobre híbrido |
| `test/` | MD5 y SHA-1 solo en pruebas |
