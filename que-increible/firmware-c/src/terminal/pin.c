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

int cifrar_pin_3des(const unsigned char clave[24], const unsigned char bloque[8], unsigned char salida[8])
{
    mbedtls_des3_context ctx;
    mbedtls_des3_init(&ctx);
    mbedtls_des3_set3key_enc(&ctx, clave);
    int r = mbedtls_des3_crypt_ecb(&ctx, bloque, salida);
    mbedtls_des3_free(&ctx);
    return r;
}

int cifrar_pin_tpv_antiguo(const unsigned char clave[8], const unsigned char bloque[8], unsigned char salida[8])
{
    mbedtls_des_context ctx;
    mbedtls_des_init(&ctx);
    mbedtls_des_setkey_enc(&ctx, clave);
    int r = mbedtls_des_crypt_ecb(&ctx, bloque, salida);
    mbedtls_des_free(&ctx);
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

/* Huella del lote de cierre del día: MD5. */
void huella_lote(const unsigned char *lote, size_t largo, unsigned char huella[16])
{
    unsigned int n = 0;
    EVP_Digest(lote, largo, huella, &n, EVP_md5(), NULL);
}
