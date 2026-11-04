# backoffice-csharp — RR. HH. y nóminas

Ficticio, de demo: la criptografía débil está **a propósito** (ver el
[README de la raíz](../../README.md)).

El backoffice de recursos humanos: nóminas, IBAN de los empleados y remesas
SEPA al banco. C# sobre .NET 8.

| Dónde | Qué lleva |
| --- | --- |
| `Nominas/CifradoNominas.cs` | IBAN en AES **ECB** con la clave en el código, nóminas en AES-GCM, **3DES** para la gestoría, PBKDF2 con HMAC-SHA1 (el valor por defecto de .NET) |
| `Nominas/FirmaRemesas.cs` | `RSACryptoServiceProvider` sin tamaño (**RSA-1024**) con **SHA-1**, RSA-3072, ECDSA P-256, ECDH P-384, MD5 y un resumen que sale de `appsettings.json` |
| `Seguridad/TokensEmpleado.cs` | JWT HMAC-SHA-256 con el secreto en el código; el banco de las remesas en **TLS 1.0 y 1.1** |
| `tests/` | DES y SHA-1 en pruebas |

Sin nada post-cuántico todavía: es la aplicación que queda por migrar.
