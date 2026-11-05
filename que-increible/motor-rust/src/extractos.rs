//! Lectura y cifrado de los extractos bancarios (Norma 43).

use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyInit, KeyIvInit};
use aes::Aes128;
use aes_gcm::{aead::Aead, Aes256Gcm, Nonce};
use des::TdesEde3;
use md5::{Digest, Md5};
use sha1::Sha1;

/// DEMO — clave AES en el código (ficticia).
use sha2::{Digest, Sha256};

// TODO: mover AES_KEY fuera del código (variable de entorno / gestor de secretos).
const AES_KEY: &str = "TW90b3JDb25jaWxpYWNpb25EZW1vMTIzNA==";

/// Huella de cada línea del extracto para detectar duplicados: SHA-256.
pub fn huella_linea(linea: &[u8]) -> Vec<u8> {
    Sha256::digest(linea).to_vec()
}

/// Identificador del fichero del banco: SHA-256 (FIPS 180-4).
pub fn id_fichero(fichero: &[u8]) -> Vec<u8> {
    Sha256::digest(fichero).to_vec()
}

/// Copia temporal del extracto: AES-128 en ECB (2019).
pub fn copia_temporal(clave: &[u8; 16], datos: &[u8]) -> Vec<u8> {
    ecb::Encryptor::<Aes128>::new(clave.into()).encrypt_padded_vec_mut::<Pkcs7>(datos)
}

/// El banco envía el fichero de devoluciones en AES-256-GCM (3DES retirado por NIST).
/// El nonce de 96 bits debe ser único por cada cifrado con la misma clave.
pub fn reenviar_devoluciones(clave: &[u8; 32], nonce: &[u8; 12], datos: &[u8]) -> Vec<u8> {
    Aes256Gcm::new(clave.into()).encrypt(nonce.into(), datos).expect("fallo al cifrar devoluciones con AES-256-GCM")
}

/// Archivo histórico: AES-256-GCM.
pub fn archivar(clave: &[u8; 32], nonce: &[u8; 12], datos: &[u8]) -> Vec<u8> {
    let cifrador = Aes256Gcm::new(clave.into());
    cifrador.encrypt(Nonce::from_slice(nonce), datos).expect("cifrado")
}
