# Demos de |QS>EDR

Código de ejemplo para enseñar [|QS>EDR](https://qic-solutions.com), la
plataforma de QiC Solutions que inventaría la criptografía de una organización,
mide su exposición a la computación cuántica y planifica la migración a
criptografía post-cuántica (PQC).

> ⚠️ **Todo es ficticio y está mal a propósito.**
>
> - La empresa, **Que Increible Compañia SL**, no existe. Su dominio,
>   `que-increible.example`, está reservado para ejemplos (RFC 2606).
> - La criptografía débil (MD5, SHA-1 al firmar, DES, 3DES, RC4, AES en ECB,
>   RSA-1024, TLS 1.0…) y las claves y secretos escritos en el código están
>   **a propósito**, para que |QS>EDR los detecte.
> - Las claves privadas y los secretos que aparecen se generaron solo para
>   estas demos: no protegen nada ni corresponden a ningún servicio real. Si un
>   escáner de secretos los señala, está haciendo su trabajo.
> - **No uses este código en producción** ni lo copies como ejemplo de buenas
>   prácticas. No todo compila de punta a punta: no hace falta para analizarlo.

## La empresa

Que Increible Compañia SL es una cadena de tiendas con venta online. Su mapa de
sistemas es el de cualquier empresa con veinte años de historia: un núcleo
contable en mainframe, SAP, una pasarela de pagos en Java, una tienda en PHP,
TPV en las tiendas, una app móvil… y criptografía de cada década.

Cada carpeta de `que-increible/` es una aplicación autocontenida, que |QS>EDR
escanea como una fuente de tipo REPOSITORY independiente (campo `subcarpeta`).

| Carpeta | Lenguajes | Qué es en la empresa |
| --- | --- | --- |
| [`pagos-java`](que-increible/pagos-java) | Java 21 + Kotlin | Pasarela de pagos. Proceso «Cobros con tarjeta», criticidad CROWN |
| [`portal-ts`](que-increible/portal-ts) | TypeScript (Node) | Portal web de clientes |
| [`api-python`](que-increible/api-python) | Python (FastAPI) | API de pedidos |
| [`gateway-go`](que-increible/gateway-go) | Go | Pasarela API interna |
| [`backoffice-csharp`](que-increible/backoffice-csharp) | C# (.NET 8) | Backoffice de RR. HH. y nóminas |
| [`tienda-php`](que-increible/tienda-php) | PHP | Tienda online |
| [`firmware-c`](que-increible/firmware-c) | C y C++ | Firmware de los TPV de tienda |
| [`motor-rust`](que-increible/motor-rust) | Rust | Motor de conciliación bancaria |
| [`app-swift`](que-increible/app-swift) | Swift | App iOS de clientes |
| [`core-cobol`](que-increible/core-cobol) | COBOL (z/OS) | Núcleo contable en mainframe, con ICSF |
| [`sap-abap`](que-increible/sap-abap) | ABAP | Extensiones de SAP (FI, remesas SEPA, HCM) |
| [`infra`](que-increible/infra) | shell, Dockerfile, Makefile, configuración | nginx, sshd, certificados y despliegue |

En cada aplicación hay, mezclado como en la vida real:

1. **Vulnerable ante un ordenador cuántico**: RSA-2048/3072, ECDSA P-256,
   ECDH, Diffie-Hellman.
2. **Roto u obsoleto hoy**: MD5, SHA-1 (al firmar y al resumir), DES, 3DES,
   RC4, AES en ECB, RSA-1024, TLS 1.0 y 1.1.
3. **Antiagilidad**: el algoritmo y el tamaño de clave escritos en la propia
   llamada, frente a algún sitio donde vienen de la configuración.
4. **Criptografía incrustada**: claves privadas y secretos HMAC/JWT en el
   código (ficticios).
5. **Ya post-cuántico o híbrido** en algún sitio: ML-KEM y ML-DSA (Bouncy
   Castle, Go 1.24, @noble/post-quantum, liboqs, Botan 3, CryptoKit de iOS 26,
   ICSF/CCA, OpenSSL 3.5) y el grupo híbrido `X25519MLKEM768` en TLS.
6. **Solo en pruebas**: algo débil en los tests, que la plataforma separa del
   inventario que puntúa.

Cada carpeta tiene su README con la historia de la aplicación y la
criptografía que lleva.

## Licencia

[MIT](LICENSE).
