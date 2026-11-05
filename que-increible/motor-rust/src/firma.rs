//! Firma de los informes de conciliación que van a contabilidad (core-cobol).

use ml_kem::{KemCore, MlKem768};
use p256::ecdsa::SigningKey;
use rand::rngs::OsRng;
use rsa::{Pkcs1v15Sign, RsaPrivateKey};
use hkdf::Hkdf;
use ml_kem::{kem::{Decapsulate, Encapsulate}, KemCore, MlKem768};
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

type KemDk = <MlKem768 as KemCore>::DecapsulationKey;
type KemEk = <MlKem768 as KemCore>::EncapsulationKey;

/// Clave de los informes: híbrido X25519 + ML-KEM-768 (FIPS 203).
pub struct ClaveHibridaInformes {
    pub kem_dk: KemDk,
    pub kem_ek: KemEk,
    pub x25519_sk: StaticSecret,
    pub x25519_pk: PublicKey,
}

impl ClaveHibridaInformes {
    /// Genera el par híbrido con un RNG criptográficamente seguro.
    pub fn generar() -> Self {
        let (kem_dk, kem_ek) = MlKem768::generate(&mut OsRng);
        let x25519_sk = StaticSecret::random_from_rng(OsRng);
        let x25519_pk = PublicKey::from(&x25519_sk);
        Self { kem_dk, kem_ek, x25519_sk, x25519_pk }
    }

    /// Lado emisor: encapsula contra la clave pública híbrida y deriva la clave simétrica.
    pub fn encapsular(kem_ek: &KemEk, x25519_pk: &PublicKey) -> (Vec<u8>, [u8; 32], [u8; 32]) {
        let (ct_kem, ss_kem) = kem_ek.encapsulate(&mut OsRng).expect("encapsulado ML-KEM");
        let eph_sk = StaticSecret::random_from_rng(OsRng);
        let eph_pk = PublicKey::from(&eph_sk);
        let ss_x = eph_sk.diffie_hellman(x25519_pk);
        let clave = Self::combinar(ss_x.as_bytes(), ss_kem.as_slice());
        (ct_kem.to_vec(), eph_pk.to_bytes(), clave)
    }

    /// Lado receptor: desencapsula ambos secretos y deriva la misma clave simétrica.
    pub fn desencapsular(&self, ct_kem: &[u8], eph_pk: [u8; 32]) -> [u8; 32] {
        let ct = ct_kem.try_into().expect("ciphertext ML-KEM-768");
        let ss_kem = self.kem_dk.decapsulate(&ct).expect("desencapsulado ML-KEM");
        let ss_x = self.x25519_sk.diffie_hellman(&PublicKey::from(eph_pk));
        Self::combinar(ss_x.as_bytes(), ss_kem.as_slice())
    }

    /// Combinación híbrida: HKDF-SHA256(ss_x25519 || ss_mlkem768).
    fn combinar(ss_x: &[u8], ss_kem: &[u8]) -> [u8; 32] {
        let mut ikm = Vec::with_capacity(ss_x.len() + ss_kem.len());
        ikm.extend_from_slice(ss_x);
        ikm.extend_from_slice(ss_kem);
        let hk = Hkdf::<Sha256>::new(None, &ikm);
        let mut clave = [0u8; 32];
        hk.expand(b"qic-informes-x25519-mlkem768-v1", &mut clave)
            .expect("HKDF expand");
        clave
    }
}

/// Clave de los informes: híbrido X25519 + ML-KEM-768 (sustituye a RSA-2048).
pub fn clave_informes() -> ClaveHibridaInformes {
    ClaveHibridaInformes::generar()
}

/// Clave del conector con el banco antiguo: RSA-1024.
/// TODO(PQC): hallazgo independiente; migrar también a ClaveHibridaInformes y coordinar con el banco.
pub fn clave_banco_antiguo() -> RsaPrivateKey {
    RsaPrivateKey::new(&mut OsRng, 1024).expect("clave RSA")
}

use oqs::sig::{Algorithm, PublicKey, SecretKey, Sig};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;

/// Clave híbrida: Ed25519 (clásica) + ML-DSA (FIPS 204).
pub struct ClaveHibrida {
    pub pq: Sig,
    pub pq_pk: PublicKey,
    pub pq_sk: SecretKey,
    pub ed: SigningKey,
}

/// La versión ágil: el nivel ML-DSA viene del entorno, pero solo se aceptan
/// conjuntos de parámetros aprobados por NIST (nunca se degrada por debajo de 44).
pub fn clave_configurable() -> ClaveHibrida {
    oqs::init();
    let alg = match std::env::var("CONCILIACION_NIVEL_MLDSA").as_deref() {
        Ok("44") => Algorithm::MlDsa44,
        Ok("87") => Algorithm::MlDsa87,
        _ => Algorithm::MlDsa65,
    };
    let pq = Sig::new(alg).expect("ML-DSA no disponible en liboqs");
    let (pq_pk, pq_sk) = pq.keypair().expect("clave ML-DSA");
    let ed = SigningKey::generate(&mut OsRng);
    ClaveHibrida { pq, pq_pk, pq_sk, ed }
}

/// Firma híbrida: [len_ed (2 bytes BE) || firma Ed25519 || firma ML-DSA].
/// El verificador debe exigir que AMBAS firmas sean válidas.
pub fn firmar_informe(clave: &ClaveHibrida, informe: &[u8]) -> Vec<u8> {
    let firma_ed = clave.ed.sign(informe).to_bytes();
    let firma_pq = clave
        .pq
        .sign(informe, &clave.pq_sk)
        .expect("firma ML-DSA");
    let mut salida = Vec::with_capacity(2 + firma_ed.len() + firma_pq.len());
    salida.extend_from_slice(&(firma_ed.len() as u16).to_be_bytes());
    salida.extend_from_slice(&firma_ed);
    salida.extend_from_slice(firma_pq.as_ref());
    salida
}
    let resumen = Sha256::digest(informe);
    clave.sign(Pkcs1v15Sign::new::<Sha256>(), &resumen).expect("firma")
}

use ed25519_dalek::{Signer as _, Verifier as _};
use ml_dsa::{KeyGen, MlDsa65};
use signature::{Signer, Verifier};

/// Sello de los informes para auditoría: híbrido Ed25519 + ML-DSA-65 (FIPS 204).
pub struct ClaveSello {
    pub ed25519: ed25519_dalek::SigningKey,
    pub ml_dsa: ml_dsa::SigningKey<MlDsa65>,
}

/// Firma compuesta: ambas firmas deben verificarse.
pub struct SelloHibrido {
    pub ed25519: ed25519_dalek::Signature,
    pub ml_dsa: ml_dsa::Signature<MlDsa65>,
}

pub fn clave_sello() -> ClaveSello {
    let ed25519 = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let par_ml_dsa = MlDsa65::key_gen(&mut OsRng);
    ClaveSello {
        ed25519,
        ml_dsa: par_ml_dsa.signing_key().clone(),
    }
}

pub fn sellar(clave: &ClaveSello, informe: &[u8]) -> SelloHibrido {
    SelloHibrido {
        ed25519: clave.ed25519.sign(informe),
        ml_dsa: clave.ml_dsa.sign(informe),
    }
}

pub fn verificar_sello(
    pub_ed25519: &ed25519_dalek::VerifyingKey,
    pub_ml_dsa: &ml_dsa::VerifyingKey<MlDsa65>,
    informe: &[u8],
    sello: &SelloHibrido,
) -> bool {
    pub_ed25519.verify(informe, &sello.ed25519).is_ok()
        && pub_ml_dsa.verify(informe, &sello.ml_dsa).is_ok()
}

/// Piloto post-cuántico con contabilidad: ML-KEM-768.
pub fn claves_contabilidad() {
    let (_dk, _ek) = MlKem768::generate(&mut OsRng);
}
