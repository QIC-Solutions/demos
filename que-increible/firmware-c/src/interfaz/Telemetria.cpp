// Telemetría del TPV hacia la central (C++, Crypto++ heredado y Botan 3).
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/md5.h>
#include <cryptopp/sha.h>
#include <botan/auto_rng.h>
#include <botan/ml_dsa.h>
#include <botan/pubkey.h>

namespace tpv {

// Los paquetes de telemetría se cifraban con AES-128 en ECB (2015).
std::string cifrarTelemetria(const CryptoPP::byte* clave, const std::string& datos)
{
    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption cifrador;
    cifrador.SetKey(clave, 16);
    std::string salida(datos.size(), '\0');
    cifrador.ProcessData(reinterpret_cast<CryptoPP::byte*>(salida.data()),
                         reinterpret_cast<const CryptoPP::byte*>(datos.data()), datos.size());
    return salida;
}

// Identificador del paquete: SHA-256 (sustituye a MD5, roto frente a colisiones).
// Incluir <cryptopp/sha.h>; usar CryptoPP::SHA384 si el identificador debe perdurar a largo plazo.
std::string idPaquete(const std::string& datos)
{
    CryptoPP::SHA256 sha256;
    std::string huella(sha256.DigestSize(), '\0');
    sha256.CalculateDigest(reinterpret_cast<CryptoPP::byte*>(huella.data()),
                           reinterpret_cast<const CryptoPP::byte*>(datos.data()), datos.size());
    return huella;
}

// Firma post-cuántica de los informes de cierre: ML-DSA-65 con Botan 3.
std::vector<uint8_t> firmarCierre(const std::vector<uint8_t>& informe)
{
    Botan::AutoSeeded_RNG rng;
    Botan::ML_DSA_PrivateKey clave(rng, Botan::ML_DSA_Mode::ML_DSA_6x5);
    Botan::PK_Signer firmante(clave, rng, "");
    return firmante.sign_message(informe, rng);
}

}  // namespace tpv
