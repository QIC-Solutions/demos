//! Pruebas: lo débil de aquí cuenta como «solo pruebas».

use des::cipher::{block_padding::NoPadding, BlockEncryptMut, KeyInit};
use des::Des;

#[test]
fn des_de_juguete() {
    let clave = b"8bytes!!";
    let salida = ecb::Encryptor::<Des>::new_from_slice(clave).unwrap().encrypt_padded_vec_mut::<NoPadding>(b"12345678");
    assert_eq!(salida.len(), 8);
}

#[test]
fn aes_gcm_del_simulador() {
    use aes_gcm::{
        aead::{Aead, AeadCore, KeyInit, OsRng},
        Aes256Gcm,
    };
    // Clave de 256 bits generada aleatoriamente (nunca hardcodeada)
    let clave = Aes256Gcm::generate_key(OsRng);
    let c = Aes256Gcm::new(&clave);
    // Nonce de 96 bits único por operación de cifrado
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let datos = b"hola";
    let cifrado = c.encrypt(&nonce, datos.as_ref()).unwrap();
    let descifrado = c.decrypt(&nonce, cifrado.as_ref()).unwrap();
    assert_eq!(&descifrado, datos);
}
