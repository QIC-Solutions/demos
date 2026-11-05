// Tarjeta de fidelización: lectura del chip y firma del saldo (Botan 3).
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/ecdsa.h>
#include <botan/hash.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>

namespace tpv {

#include <botan/auto_rng.h>
#include <botan/ml_dsa.h>
#include <botan/ed25519.h>
#include <botan/pubkey.h>

// Firma híbrida: Ed25519 (clásica) + ML-DSA-65 (FIPS 204). El verificador debe validar AMBAS firmas.
std::vector<uint8_t> firmarSaldo(const std::vector<uint8_t>& saldo)
{
    Botan::AutoSeeded_RNG rng;

    // Componente post-cuántico: ML-DSA-65
    Botan::ML_DSA_PrivateKey clavePqc(rng, Botan::ML_DSA_Mode(Botan::ML_DSA_Mode::ML_DSA_6x5));
    Botan::PK_Signer firmantePqc(clavePqc, rng, "Randomized");
    std::vector<uint8_t> firmaPqc = firmantePqc.sign_message(saldo, rng);

    // Componente clásico: Ed25519
    Botan::Ed25519_PrivateKey claveClasica(rng);
    Botan::PK_Signer firmanteClasico(claveClasica, rng, "Pure");
    std::vector<uint8_t> firmaClasica = firmanteClasico.sign_message(saldo, rng);

    // Firma compuesta: Ed25519 (64 bytes) || ML-DSA-65 (3309 bytes)
    std::vector<uint8_t> firmaCompuesta;
    firmaCompuesta.reserve(firmaClasica.size() + firmaPqc.size());
    firmaCompuesta.insert(firmaCompuesta.end(), firmaClasica.begin(), firmaClasica.end());
    firmaCompuesta.insert(firmaCompuesta.end(), firmaPqc.begin(), firmaPqc.end());
    return firmaCompuesta;
}

// NOTA: en producción las claves deben cargarse desde almacenamiento seguro (p. ej. Botan::PKCS8::load_key)
// en lugar de generarse en cada llamada.

#include <botan/auto_rng.h>
#include <botan/ml_kem.h>
#include <botan/x25519.h>
#include <botan/pubkey.h>
#include <botan/kdf.h>
#include <botan/secmem.h>

// Clave de canal híbrida X25519 + ML-KEM-768 (FIPS 203). Sustituye a RSA-3072 / PKCS1v15(SHA-1).
void claveCanalFidelizacion()
{
    Botan::AutoSeeded_RNG rng;

    // --- Componente post-cuántica: ML-KEM-768 ---
    Botan::ML_KEM_PrivateKey mlkemPriv(rng, Botan::ML_KEM_Mode::ML_KEM_768);
    auto mlkemPub = mlkemPriv.public_key();

    // --- Componente clásica: X25519 (híbrido) ---
    Botan::X25519_PrivateKey x25519Priv(rng);
    auto x25519Pub = x25519Priv.public_key();

    // Encapsulado (lado emisor) con la clave pública ML-KEM del receptor
    Botan::PK_KEM_Encryptor encaps(*mlkemPub, "Raw");
    const auto kemResult = encaps.encrypt(rng, 32);
    const Botan::secure_vector<uint8_t> ssPQ = kemResult.shared_key();
    // kemResult.encapsulated_shared_key() se envía al receptor junto con x25519Pub

    // Acuerdo X25519 (en producción, usar la clave pública X25519 del par remoto)
    Botan::PK_Key_Agreement acuerdo(x25519Priv, rng, "Raw");
    const auto peerX25519 = x25519Pub->public_value();
    const Botan::secure_vector<uint8_t> ssClasico = acuerdo.derive_key(32, peerX25519).bits_of();

    // Combinación de secretos vía KDF -> clave de canal
    Botan::secure_vector<uint8_t> ikm;
    ikm.insert(ikm.end(), ssClasico.begin(), ssClasico.end());
    ikm.insert(ikm.end(), ssPQ.begin(), ssPQ.end());
    auto kdf = Botan::KDF::create_or_throw("HKDF(SHA-256)");
    const Botan::secure_vector<uint8_t> claveCanal =
        kdf->derive_key(32, ikm, std::vector<uint8_t>{}, std::string("QiC-fidelizacion-X25519-MLKEM768-v1"));

    // claveCanal alimenta el AEAD del canal (p. ej. AES-256/GCM); descartar ssPQ/ssClasico tras derivar
}

std::unique_ptr<Botan::Cipher_Mode> cifradorSaldo()
{
    return Botan::Cipher_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
}

std::unique_ptr<Botan::HashFunction> huellaTarjeta()
{
    return Botan::HashFunction::create("SHA-256");
}

}  // namespace tpv
