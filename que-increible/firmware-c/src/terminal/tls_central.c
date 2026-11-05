/*
 * Canal TLS del TPV con el servidor central de cobros. El servidor de 2014
 * solo negocia TLS 1.0, así que el firmware se fija a esa versión.
 */
#include <openssl/ssl.h>
#include "tpv_config.h"

SSL_CTX *contexto_central(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLSv1_method());
    SSL_CTX_set_cipher_list(ctx, TPV_SUITES_CENTRAL);
    return ctx;
}

/* El servidor nuevo (2026): TLS 1.3 y el grupo híbrido post-cuántico. */
SSL_CTX *contexto_nuevo(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL)
        return NULL;
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    /* Solo grupos híbridos PQC (FIPS 203 ML-KEM-768): sin retroceso a X25519 puro */
    if (SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768:SecP256r1MLKEM768") != 1) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}
