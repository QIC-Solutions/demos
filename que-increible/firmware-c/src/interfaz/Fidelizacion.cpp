// Tarjeta de fidelización: lectura del chip y firma del saldo (Botan 3).
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/ecdsa.h>
#include <botan/hash.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>

namespace tpv {

void firmarSaldo(const std::vector<uint8_t>& saldo)
{
    Botan::AutoSeeded_RNG rng;
    Botan::ECDSA_PrivateKey clave(rng, Botan::EC_Group::from_name("secp256r1"));
    Botan::PK_Signer firmante(clave, rng, "EMSA1(SHA-256)");
    firmante.sign_message(saldo, rng);
}

void claveCanalFidelizacion()
{
    Botan::AutoSeeded_RNG rng;
    Botan::RSA_PrivateKey rsa(rng, 3072);
    Botan::PK_Signer heredada(rsa, rng, "PKCS1v15(SHA-1)");
}

std::unique_ptr<Botan::Cipher_Mode> cifradorSaldo()
{
    return Botan::Cipher_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
}

std::unique_ptr<Botan::HashFunction> huellaTarjeta()
{
    return Botan::HashFunction::create("SHA-1");
}

}  // namespace tpv
