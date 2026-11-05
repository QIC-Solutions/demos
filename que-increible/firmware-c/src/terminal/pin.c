/*
 * Cifrado del bloque de PIN en el TPV (ISO 9564). El HSM del adquirente
 * todavía exige Triple DES con la clave de zona; los TPV de 2012 que quedan
 * en tienda solo tienen DES simple en el chip.
 */
#include <string.h>
#include <mbedtls/des.h>
#include <openssl/evp.h>

/* DEMO — clave de transporte del PIN, en el firmware (ficticia). */
static const char *MASTER_KEY = "VFBWUXVlSW5jcmVpYmxlRGVtb01hZXN0cmE=";

#include "mbedtls/gcm.h"

/* clave: 32 bytes (AES-256), iv: 12 bytes unico por operacion, tag: 16 bytes */
int cifrar_pin_aes_gcm(const unsigned char clave[32], const unsigned char iv[12],
                       const unsigned char bloque[8], unsigned char salida[8],
                       unsigned char tag[16])
{
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int r = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, clave, 256);
    if (r == 0) {
        r = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, 8,
                                      iv, 12, NULL, 0,
                                      bloque, salida, 16, tag);
    }
    mbedtls_gcm_free(&ctx);
    return r;
}

#include "mbedtls/gcm.h"

/* clave: 32 bytes (AES-256); iv: 12 bytes UNICO por operacion; tag: 16 bytes de autenticacion */
int cifrar_pin_tpv(const unsigned char clave[32], const unsigned char iv[12],
                   const unsigned char *bloque, size_t len,
                   unsigned char *salida, unsigned char tag[16])
{
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int r = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, clave, 256);
    if (r == 0) {
        r = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, len,
                                      iv, 12,
                                      NULL, 0,      /* AAD opcional: p. ej. ID de terminal/transaccion */
                                      bloque, salida,
                                      16, tag);
    }
    mbedtls_gcm_free(&ctx);
    return r;
}

/* Registro de transacciones en la memoria del TPV: AES-128 en ECB. */
int cifrar_registro(const unsigned char clave[16], const unsigned char *entrada, int largo, unsigned char *salida)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int escrito = 0, total = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, clave, NULL);
    EVP_EncryptUpdate(ctx, salida, &escrito, entrada, largo);
    total = escrito;
    EVP_EncryptFinal_ex(ctx, salida + escrito, &escrito);
    EVP_CIPHER_CTX_free(ctx);
    return total + escrito;
}

/* Huella del lote de cierre del día: SHA-256 (FIPS 180-4). */
#define HUELLA_LOTE_LEN 32

void huella_lote(const unsigned char *lote, size_t largo, unsigned char huella[HUELLA_LOTE_LEN])
{
    unsigned int n = 0;
    EVP_Digest(lote, largo, huella, &n, EVP_sha256(), NULL);
}
