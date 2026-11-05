//! Pruebas: lo débil de aquí cuenta como «solo pruebas».

use des::cipher::{block_padding::NoPadding, BlockEncryptMut, KeyInit};
use des::Des;

#[test]
fn des_de_juguete() {
    let clave = b"8bytes!!";
    let salida = ecb::Encryptor::<Des>::new_from_slice(clave).unwrap().encrypt_padded_vec_mut::<NoPadding>(b"12345678");
    assert_eq!(salida.len(), 8);
}

// La generación automática no estuvo disponible. Aplicar la recomendación PQC indicada sobre el código detectado.
