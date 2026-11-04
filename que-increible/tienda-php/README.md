# tienda-php — tienda online

Ficticia, de demo: la criptografía débil está **a propósito** (ver el
[README de la raíz](../../README.md)).

La tienda online, en PHP 8.2.

| Dónde | Qué lleva |
| --- | --- |
| `src/Clientes/Contrasenas.php` | Contraseñas heredadas en **MD5** sin sal, las nuevas en Argon2id, token de «recordarme» con SHA-1 |
| `src/Clientes/Carrito.php` | Carritos en **3DES** y cupones en **RC4** con la clave en el código; copias en AES-128 **ECB**; la versión nueva elige el cifrado en `config/tienda.php` |
| `src/Pagos/Pasarela.php` | HMAC con el secreto en el código, claves RSA-2048 y EC P-256, firma con **SHA-1**, **TLS 1.0** con la pasarela antigua y sobres de libsodium (X25519) |
| `src/Pagos/ClaveTpvVirtual.php` | Una clave privada PEM incrustada (ficticia) |
| `tests/` | MD5 y Blowfish solo en pruebas |
