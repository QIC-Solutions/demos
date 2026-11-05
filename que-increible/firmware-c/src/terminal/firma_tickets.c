/*
 * Firma de los tickets electrónicos que el TPV envía al cliente por correo.
 * El tamaño de la clave sale de tpv_config.h (1024 bits, de 2012).
 */
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include "tpv_config.h"

EVP_PKEY *clave_tickets(void)
{
    EVP_PKEY *clave = NULL;
    /* Híbrido X25519 + ML-KEM-768 (FIPS 203), nativo en OpenSSL >= 3.5.
     * Con oqs-provider usar "x25519_mlkem768". */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, TPV_ALG_TICKETS, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &clave);
    EVP_PKEY_CTX_free(ctx);
    return clave;
}

/* Encapsular hacia la clave pública del terminal (lado emisor). */
int encapsular_tickets(EVP_PKEY *pub, unsigned char *ct, size_t *ct_len,
                       unsigned char *ss, size_t *ss_len)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pub, NULL);
    int ok = ctx != NULL
          && EVP_PKEY_encapsulate_init(ctx, NULL) > 0
          && EVP_PKEY_encapsulate(ctx, ct, ct_len, ss, ss_len) > 0;
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

/* Decapsular en el terminal (lado receptor). */
int decapsular_tickets(EVP_PKEY *priv, const unsigned char *ct, size_t ct_len,
                       unsigned char *ss, size_t *ss_len)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, priv, NULL);
    int ok = ctx != NULL
          && EVP_PKEY_decapsulate_init(ctx, NULL) > 0
          && EVP_PKEY_decapsulate(ctx, ss, ss_len, ct, ct_len) > 0;
    EVP_PKEY_CTX_free(ctx);
    return ok;
}
/* En el .h: #define TPV_ALG_TICKETS "X25519MLKEM768"  (sustituye a TPV_BITS_TICKETS) */
    return clave;
}

/* Firma del ticket: SHA-256 con RSA (SHA-1 retirado por estar deprecado por NIST). */
int firmar_ticket(EVP_PKEY *clave, const unsigned char *ticket, size_t largo, unsigned char *firma, size_t *largo_firma)
{
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (md == NULL)
        return 0;
    /* Para tickets de larga duración usar EVP_sha384() o EVP_sha3_256() */
    if (EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, clave) != 1) {
        EVP_MD_CTX_free(md);
        return 0;
    }
    int r = EVP_DigestSign(md, firma, largo_firma, ticket, largo);
    EVP_MD_CTX_free(md);
    return r;
}

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <string.h>

/* Clave del lector NFC: KEM híbrido X25519 + ML-KEM-768 (FIPS 203).
 * Si la clave se usa para FIRMAR tickets, sustituir "X25519"/"ML-KEM-768"
 * por "ML-DSA-65" (FIPS 204) y usar EVP_DigestSign/EVP_DigestVerify. */
typedef struct {
    EVP_PKEY *x25519;    /* componente clásica (transición)      */
    EVP_PKEY *mlkem768;  /* componente post-cuántica (FIPS 203) */
} clave_hibrida_t;

static EVP_PKEY *generar_clave(const char *alg)
{
    EVP_PKEY *clave = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    if (ctx == NULL)
        return NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &clave) <= 0) {
        EVP_PKEY_free(clave);
        clave = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return clave;
}

int clave_lector_nfc(clave_hibrida_t *out)
{
    memset(out, 0, sizeof(*out));
    out->x25519   = generar_clave("X25519");
    out->mlkem768 = generar_clave("ML-KEM-768");
    if (out->x25519 == NULL || out->mlkem768 == NULL) {
        EVP_PKEY_free(out->x25519);
        EVP_PKEY_free(out->mlkem768);
        memset(out, 0, sizeof(*out));
        return -1;
    }
    return 0;
}

/* Combina los dos secretos compartidos (X25519 || ML-KEM-768) con HKDF-SHA256. */
int derivar_clave_hibrida(const unsigned char *ss_x25519, size_t ss_x25519_len,
                          const unsigned char *ss_mlkem, size_t ss_mlkem_len,
                          unsigned char *clave_out, size_t clave_out_len)
{
    unsigned char ikm[32 + 32];
    int rc = -1;
    if (ss_x25519_len != 32 || ss_mlkem_len != 32)
        return -1;
    memcpy(ikm, ss_x25519, 32);
    memcpy(ikm + 32, ss_mlkem, 32);

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *kctx = kdf ? EVP_KDF_CTX_new(kdf) : NULL;
    if (kctx != NULL) {
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0),
            OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm, sizeof(ikm)),
            OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                              "QiC-NFC-X25519-MLKEM768-v1", 26),
            OSSL_PARAM_construct_end()
        };
        if (EVP_KDF_derive(kctx, clave_out, clave_out_len, params) > 0)
            rc = 0;
    }
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    OPENSSL_cleanse(ikm, sizeof(ikm));
    return rc;
}

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>

/* Clave del canal con la central: híbrido X25519 + ML-KEM-768 (FIPS 203).
 * Los secretos de ambos KEM se combinan con HKDF-SHA256 (ver derivar_secreto_canal). */
typedef struct {
    EVP_PKEY *x25519;
    EVP_PKEY *mlkem768;
} clave_canal_t;

int clave_canal(clave_canal_t *k)
{
    k->x25519   = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
    k->mlkem768 = EVP_PKEY_Q_keygen(NULL, NULL, "ML-KEM-768");
    if (k->x25519 == NULL || k->mlkem768 == NULL) {
        EVP_PKEY_free(k->x25519);
        EVP_PKEY_free(k->mlkem768);
        k->x25519 = k->mlkem768 = NULL;
        return 0;
    }
    return 1;
}

void clave_canal_free(clave_canal_t *k)
{
    EVP_PKEY_free(k->x25519);
    EVP_PKEY_free(k->mlkem768);
    k->x25519 = k->mlkem768 = NULL;
}

/* Combina ss_x25519 || ss_mlkem en una clave de canal de 32 bytes (HKDF-SHA256). */
int derivar_secreto_canal(const unsigned char *ss_x25519, size_t ss_x25519_len,
                          const unsigned char *ss_mlkem, size_t ss_mlkem_len,
                          unsigned char out[32])
{
    unsigned char ikm[32 + 32];
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[4];
    int ok = 0;

    if (ss_x25519_len != 32 || ss_mlkem_len != 32)
        return 0;
    memcpy(ikm, ss_x25519, 32);
    memcpy(ikm + 32, ss_mlkem, 32);

    if ((kdf = EVP_KDF_fetch(NULL, "HKDF", NULL)) == NULL ||
        (kctx = EVP_KDF_CTX_new(kdf)) == NULL)
        goto fin;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm, sizeof(ikm));
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                    (void *)"canal-central-x25519-mlkem768", 29);
    params[3] = OSSL_PARAM_construct_end();

    ok = EVP_KDF_derive(kctx, out, 32, params) == 1;

fin:
    OPENSSL_cleanse(ikm, sizeof(ikm));
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ok;
}
