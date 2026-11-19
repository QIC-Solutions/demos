# integraciones-ruby — integraciones con proveedores

Ficticia, de demo: la criptografía débil está **a propósito** (ver el
[README de la raíz](../../README.md)).

Los trabajos que intercambian ficheros con los proveedores de la empresa
(transportistas, el banco y los mayoristas del catálogo), en Ruby 3.3.

| Dónde | Qué lleva |
| --- | --- |
| `lib/integraciones/transportista.rb` | Envío de albaranes por HTTPS con **TLS 1.0** y sin verificar el certificado; albaranes firmados con **RSA-1024** y **SHA-1** |
| `lib/integraciones/banco.rb` | Extractos del banco en **3DES**, su control en **MD5** y su firma con un HMAC-SHA-1 con el secreto en el código; la versión nueva, en AES-256-GCM con la clave derivada por HKDF |
| `lib/integraciones/catalogo.rb` | El catálogo de un mayorista antiguo en **RC4**, la clave sacada de una frase con PBKDF2-HMAC-SHA-1 y 1.000 iteraciones; los mayoristas nuevos, por TLS 1.2 o 1.3 |
| `config/integraciones.yml` | Qué cifrado usa cada proveedor: la parte que sí se puede cambiar sin tocar código |
| `spec/` | MD5 y SHA-1 solo en pruebas |
