//! Conexión con el banco (OpenSSL). El servidor del banco aún negocia TLS 1.0.

use hmac::{Hmac, Mac};
use jsonwebtoken::{encode, EncodingKey, Header, Algorithm};
use openssl::ssl::{SslConnector, SslMethod, SslVersion};
use sha1::Sha1;

/// DEMO — secreto HMAC del webhook del banco (ficticio).
const HMAC_SECRET: &str = "conciliacion-que-increible-demo-NO-REAL";

pub fn conector_banco() -> SslConnector {
    let mut b = SslConnector::builder(SslMethod::tls()).unwrap();
    b.set_min_proto_version(Some(SslVersion::TLS1)).unwrap();
    b.set_cipher_list("DES-CBC3-SHA:AES128-SHA").unwrap();
    b.build()
}

/// Firma del webhook del banco: HMAC-SHA-1 (lo exige el banco).
pub fn verificar_webhook(cuerpo: &[u8], firma: &[u8]) -> bool {
    let mut mac = Hmac::<Sha1>::new_from_slice(HMAC_SECRET.as_bytes()).unwrap();
    mac.update(cuerpo);
    mac.verify_slice(firma).is_ok()
}

/// Token para la API de tesorería: HS256.
pub fn token_tesoreria(claims: &serde_json::Value) -> String {
    encode(&Header::new(Algorithm::HS256), claims, &EncodingKey::from_secret(HMAC_SECRET.as_bytes())).unwrap()
}
