//! Lectura y cifrado de los extractos bancarios (Norma 43).

use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyInit, KeyIvInit};
use aes::Aes128;
use aes_gcm::{aead::Aead, Aes256Gcm, Nonce};
use des::TdesEde3;
use md5::{Digest, Md5};
use sha1::Sha1;

/// DEMO — clave AES en el código (ficticia).
const AES_KEY: &str = "TW90b3JDb25jaWxpYWNpb25EZW1vMTIzNA==";

/// Huella de cada línea del extracto para detectar duplicados: MD5.
pub fn huella_linea(linea: &[u8]) -> Vec<u8> {
    Md5::digest(linea).to_vec()
}

/// Identificador del fichero del banco: SHA-1.
pub fn id_fichero(fichero: &[u8]) -> Vec<u8> {
    Sha1::digest(fichero).to_vec()
}

/// Copia temporal del extracto: AES-128 en ECB (2019).
pub fn copia_temporal(clave: &[u8; 16], datos: &[u8]) -> Vec<u8> {
    ecb::Encryptor::<Aes128>::new(clave.into()).encrypt_padded_vec_mut::<Pkcs7>(datos)
}

/// El banco envía el fichero de devoluciones en Triple DES.
pub fn reenviar_devoluciones(clave: &[u8; 24], iv: &[u8; 8], datos: &[u8]) -> Vec<u8> {
    cbc::Encryptor::<TdesEde3>::new(clave.into(), iv.into()).encrypt_padded_vec_mut::<Pkcs7>(datos)
}

/// Archivo histórico: AES-256-GCM.
pub fn archivar(clave: &[u8; 32], nonce: &[u8; 12], datos: &[u8]) -> Vec<u8> {
    let cifrador = Aes256Gcm::new(clave.into());
    cifrador.encrypt(Nonce::from_slice(nonce), datos).expect("cifrado")
}
