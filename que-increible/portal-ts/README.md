# portal-ts — portal web de clientes

Ficticio, de demo: la criptografía débil está **a propósito** (ver el
[README de la raíz](../../README.md)).

El portal donde los clientes de Que Increible Compañia SL consultan sus
pedidos, sus tarjetas guardadas y su monedero. TypeScript sobre Node 22.

| Dónde | Qué lleva |
| --- | --- |
| `src/auth/sesion.ts` | JWT HS256 con el secreto en el código, RS256 para la app y la versión ágil con el algoritmo en el entorno |
| `src/cripto/datos.ts` | Preferencias en AES-128 **ECB**, historial en AES-256-GCM, MD5 y SHA-1, cupones en **3DES** (crypto-js), pares RSA-2048 y ECDSA P-256, firma con SHA-1 |
| `src/cripto/postcuantico.ts` | **ML-KEM-768** y **ML-DSA-65** con `@noble/post-quantum` |
| `src/tls/servidor.ts` | Servidor HTTPS con `minVersion: 'TLSv1'` y suites 3DES y RC4 |
| `test/` | MD4 y DES solo en pruebas |
