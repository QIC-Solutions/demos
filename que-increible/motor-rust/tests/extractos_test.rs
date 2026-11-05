//! Pruebas: lo débil de aquí cuenta como «solo pruebas».

use des::cipher::{block_padding::NoPadding, BlockEncryptMut, KeyInit};
use des::Des;

#[test]
fn aes_gcm_de_juguete() {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    // Clave de 256 bits (32 bytes). En producción cargar desde gestor de secretos, nunca hardcodear.
    let clave = [0x42u8; 32];
    let cifrador = Aes256Gcm::new_from_slice(&clave).unwrap();
    // Nonce de 96 bits: debe ser único por cada operación de cifrado con la misma clave.
    let nonce = Nonce::from_slice(b"nonce_unico1");
    let salida = cifrador.encrypt(nonce, b"12345678".as_ref()).unwrap();
    // Texto cifrado (8 bytes) + tag de autenticación GCM (16 bytes)
    assert_eq!(salida.len(), 8 + 16);
}

#[test]
fn aes_gcm_del_simulador() {
    use aes_gcm::{
        aead::{Aead, AeadCore, KeyInit, OsRng},
        Aes256Gcm,
    };
    // Clave de 256 bits generada aleatoriamente (nunca embebida en el código)
    let clave = Aes256Gcm::generate_key(OsRng);
    let c = Aes256Gcm::new(&clave);
    // Nonce único de 96 bits por cada operación de cifrado
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let datos = b"hola";
    let cifrado = c.encrypt(&nonce, datos.as_ref()).unwrap();
    let descifrado = c.decrypt(&nonce, cifrado.as_ref()).unwrap();
    assert_eq!(&descifrado, datos);
}
