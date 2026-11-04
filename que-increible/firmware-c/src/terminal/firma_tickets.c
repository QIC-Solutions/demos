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
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, TPV_BITS_TICKETS);
    EVP_PKEY_keygen(ctx, &clave);
    EVP_PKEY_CTX_free(ctx);
    return clave;
}

/* Firma del ticket: SHA-1 con RSA (heredado). */
int firmar_ticket(EVP_PKEY *clave, const unsigned char *ticket, size_t largo, unsigned char *firma, size_t *largo_firma)
{
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_DigestSignInit(md, NULL, EVP_sha1(), NULL, clave);
    int r = EVP_DigestSign(md, firma, largo_firma, ticket, largo);
    EVP_MD_CTX_free(md);
    return r;
}

/* Clave del lector NFC: ECDSA sobre P-256. */
EC_KEY *clave_lector_nfc(void)
{
    EC_KEY *clave = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(clave);
    return clave;
}

/* Clave del canal con la central: RSA-2048. */
EVP_PKEY *clave_canal(void)
{
    return EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
}
