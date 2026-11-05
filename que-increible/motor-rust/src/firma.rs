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

// La generación automática no estuvo disponible. Aplicar la recomendación PQC indicada sobre el código detectado.
    let resumen = Sha256::digest(informe);
    clave.sign(Pkcs1v15Sign::new::<Sha256>(), &resumen).expect("firma")
// La generación automática no estuvo disponible. Aplicar la recomendación PQC indicada sobre el código detectado.
    let (_dk, _ek) = MlKem768::generate(&mut OsRng);
}
