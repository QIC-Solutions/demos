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

/// La versión ágil: el tamaño viene del entorno.
pub fn clave_configurable() -> RsaPrivateKey {
    let bits: usize = std::env::var("CONCILIACION_BITS_RSA").unwrap_or_default().parse().unwrap_or(3072);
    RsaPrivateKey::new(&mut OsRng, bits).expect("clave RSA")
}

pub fn firmar_informe(clave: &RsaPrivateKey, informe: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let resumen = Sha256::digest(informe);
    clave.sign(Pkcs1v15Sign::new::<Sha256>(), &resumen).expect("firma")
}

/// Sello de los informes para auditoría: ECDSA P-256.
pub fn clave_sello() -> SigningKey {
    SigningKey::random(&mut OsRng)
}

/// Piloto post-cuántico con contabilidad: ML-KEM-768.
pub fn claves_contabilidad() {
    let (_dk, _ek) = MlKem768::generate(&mut OsRng);
}
