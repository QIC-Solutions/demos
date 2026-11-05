/* Pruebas: lo débil de aquí cuenta como «solo pruebas». */
#include <assert.h>
#include <openssl/evp.h>

int main(void)
{
    unsigned char h[16];
    unsigned int n = 0;
    EVP_Digest("fixture", 7, h, &n, EVP_md4(), NULL);
    assert(n == 16);
    /* Clave AES-256 de prueba (32 bytes) e IV de 96 bits: en producción cargar desde un gestor de secretos */
    static const unsigned char key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f };
    unsigned char iv[12];
    assert(RAND_bytes(iv, sizeof(iv)) == 1);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    assert(ctx != NULL);
    assert(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1);
    assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL) == 1);
    assert(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) == 1);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
