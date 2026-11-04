/* Pruebas: lo débil de aquí cuenta como «solo pruebas». */
#include <assert.h>
#include <openssl/evp.h>

int main(void)
{
    unsigned char h[16];
    unsigned int n = 0;
    EVP_Digest("fixture", 7, h, &n, EVP_md4(), NULL);
    assert(n == 16);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_rc4(), NULL, (const unsigned char *)"clave-de-prueba!", NULL);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
