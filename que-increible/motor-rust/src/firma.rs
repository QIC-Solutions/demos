//! Firma de los informes de conciliación que van a contabilidad (core-cobol).

use ml_kem::{KemCore, MlKem768};
use p256::ecdsa::SigningKey;
use rand::rngs::OsRng;
use rsa::{Pkcs1v15Sign, RsaPrivateKey};
use sha2::Sha256;

/// Clave de los informes: RSA-2048 escrita en la llamada.
pub fn clave_informes() -> RsaPrivateKey {
    RsaPrivateKey::new(&mut OsRng, 2048).expect("clave RSA")
}

/// Clave del conector con el banco antiguo: RSA-1024.
pub fn clave_banco_antiguo() -> RsaPrivateKey {
    RsaPrivateKey::new(&mut OsRng, 1024).expect("clave RSA")
}

use ml_dsa::{KeyGen, MlDsa65, SigningKey};
use ml_dsa::signature::Signer;
use rand_core::OsRng;

/// La versión ágil: el conjunto de parámetros viene del entorno,
/// pero SOLO se admiten parámetros ML-DSA (FIPS 204); RSA queda eliminado.
pub fn clave_configurable() -> SigningKey<MlDsa65> {
    let nivel = std::env::var("CONCILIACION_NIVEL_MLDSA").unwrap_or_else(|_| "65".into());
    if nivel != "65" {
        eprintln!("aviso: solo ML-DSA-65 está habilitado en este motor; se ignora CONCILIACION_NIVEL_MLDSA={nivel}");
    }
    let par = MlDsa65::key_gen(&mut OsRng);
    par.signing_key().clone()
}

pub fn firmar_informe(clave: &SigningKey<MlDsa65>, informe: &[u8]) -> Vec<u8> {
    // ML-DSA firma el mensaje completo internamente (no hace falta pre-hash con sha2).
    clave.sign(informe).encode().to_vec()
}
    let resumen = Sha256::digest(informe);
    clave.sign(Pkcs1v15Sign::new::<Sha256>(), &resumen).expect("firma")
}

/// Sello de los informes para auditoría: híbrido Ed25519 + ML-DSA-65 (FIPS 204).
/// Ambas firmas deben emitirse y verificarse durante la migración.
pub struct ClaveSello {
    pub ed25519: ed25519_dalek::SigningKey,
    pub ml_dsa: ml_dsa::KeyPair<ml_dsa::MlDsa65>,
}

pub fn clave_sello() -> ClaveSello {
    ClaveSello {
        ed25519: ed25519_dalek::SigningKey::generate(&mut OsRng),
        ml_dsa: ml_dsa::MlDsa65::key_gen(&mut OsRng),
    }
}

/// Piloto post-cuántico con contabilidad: ML-KEM-768.
pub fn claves_contabilidad() {
    let (_dk, _ek) = MlKem768::generate(&mut OsRng);
}
