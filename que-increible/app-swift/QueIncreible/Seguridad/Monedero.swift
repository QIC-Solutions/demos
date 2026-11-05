import CryptoKit
import Foundation
import Security

/// Monedero de la app: tarjetas guardadas y pago con el móvil en tienda.
struct Monedero {

    /// Tarjetas guardadas en el llavero: AES-256-GCM (CryptoKit).
    func guardarTarjeta(_ datos: Data, clave: SymmetricKey) throws -> Data {
        try AES.GCM.seal(datos, using: clave).combined!
    }

    /// Clave del dispositivo para firmar los pagos: híbrido Ed25519 + ML-DSA-65 (FIPS 204).
    /// Se verifican AMBAS firmas; resistente a Shor gracias a la componente ML-DSA.
    struct ClaveDispositivoHibrida {
        let clasica: Curve25519.Signing.PrivateKey
        let pqc: MLDSA65.PrivateKey

        func firmar(_ datos: Data) throws -> (clasica: Data, pqc: Data) {
            (clasica.signature(for: datos), try pqc.signature(for: datos))
        }

        func verificar(_ firma: (clasica: Data, pqc: Data), para datos: Data) -> Bool {
            clasica.publicKey.isValidSignature(firma.clasica, for: datos)
                && pqc.publicKey.isValidSignature(firma.pqc, for: datos)
        }
    }

    func claveDispositivo() throws -> ClaveDispositivoHibrida {
        ClaveDispositivoHibrida(
            clasica: Curve25519.Signing.PrivateKey(),
            pqc: try MLDSA65.PrivateKey()
        )
    }

    /// Clave del canal antiguo con el TPV (2018): RSA-1024 en el llavero.
    func claveTpvAntiguo() -> SecKey? {
        let atributos: [String: Any] = [
            import CryptoKit

    /// Par de claves híbrido X25519 + ML-KEM-768 (X-Wing, FIPS 203) en sustitución de RSA-1024.
    func generarClaveMonedero() -> XWingMLKEM768X25519.PrivateKey {
        let clavePrivada = XWingMLKEM768X25519.PrivateKey()
        // Persistir clavePrivada.rawRepresentation en el llavero (kSecAttrAccessibleWhenUnlockedThisDeviceOnly).
        // Distribuir ÚNICAMENTE clavePrivada.publicKey.rawRepresentation al TPV.
        return clavePrivada
    }

    /// Protección del recibo para el TPV: encapsulación híbrida (X25519 + ML-KEM-768) + AES-256-GCM.
    /// Sustituye el uso de RSA PKCS#1 v1.5 con SHA-1.
    func protegerRecibo(_ recibo: Data, clavePublica: XWingMLKEM768X25519.PublicKey) throws -> (encapsulado: Data, cifrado: Data) {
        let resultado = try clavePublica.encapsulate()
        let claveSimetrica = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: resultado.sharedSecret,
            info: Data("QueIncreible-recibo-v2".utf8),
            outputByteCount: 32
        )
        let sellado = try AES.GCM.seal(recibo, using: claveSimetrica)
        return (resultado.encapsulated, sellado.combined!)
    }

    /// Desencapsulación en el receptor.
    func abrirRecibo(encapsulado: Data, cifrado: Data, clave: XWingMLKEM768X25519.PrivateKey) throws -> Data {
        let secreto = try clave.decapsulate(encapsulado)
        let claveSimetrica = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: secreto,
            info: Data("QueIncreible-recibo-v2".utf8),
            outputByteCount: 32
        )
        return try AES.GCM.open(try AES.GCM.SealedBox(combined: cifrado), using: claveSimetrica)
    }

    // TODO: migrar firmarReciboAntiguo (PKCS#1 v1.5 + SHA-1) a ML-DSA-65 (FIPS 204, CryptoKit MLDSA65) en híbrido con Ed25519.
        var error: Unmanaged<CFError>?
        return SecKeyCreateSignature(clave, .rsaSignatureMessagePKCS1v15SHA1, recibo as CFData, &error) as Data?
    }

    /// iOS 26: el pago en tienda encapsula la clave de sesión con ML-KEM-768.
    func sesionPostCuantica() throws -> MLKEM768.PrivateKey {
        try MLKEM768.PrivateKey()
    }

    /// Y firma el ticket con ML-DSA-65.
    func firmarTicket(_ ticket: Data) throws -> Data {
        let clave = try MLDSA65.PrivateKey()
        return try clave.signature(for: ticket)
    }

    /// Huella del ticket para la caché: SHA-256 (CryptoKit).
    func huellaTicket(_ ticket: Data) -> SHA256Digest {
        SHA256.hash(data: ticket)
    }

    /// Identificador del dispositivo: SHA-256.
    func idDispositivo(_ datos: Data) -> SHA256Digest {
        SHA256.hash(data: datos)
    }
}
