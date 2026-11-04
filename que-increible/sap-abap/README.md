# sap-abap — extensiones de SAP

Ficticias, de demo: la criptografía débil está **a propósito** (ver el
[README de la raíz](../../README.md)).

Desarrollos Z de SAP (formato abapGit): facturas en FI, remesas SEPA a
proveedores y nóminas de HCM hacia el backoffice.

| Dónde | Qué lleva |
| --- | --- |
| `src/zcl_qi_huellas_facturas.clas.abap` | `CL_ABAP_MESSAGE_DIGEST` con SHA-256, sin algoritmo (SHA-1, el de SAP) y MD5; `CL_ABAP_HMAC` con el secreto en el código y sin algoritmo (HMAC-SHA-1) |
| `src/zqi_remesas_sepa.prog.abap` | `SSF_KRN_SIGN` PKCS #7 con **SHA-1**, `SSF_KRN_ENVELOPE` con el cifrado leído de una tabla de parametrización, `MD5_CALCULATE_HASH_FOR_CHAR` |
| `src/zcl_qi_xml_nominas.clas.abap` | `CL_SEC_SXML_WRITER`: **3DES-CBC** por defecto, AES-256-CBC y HMAC-SHA-256 |
| `tests/` | HMAC-MD5 solo en pruebas |

SAP no ofrece todavía nada post-cuántico en estas APIs.
