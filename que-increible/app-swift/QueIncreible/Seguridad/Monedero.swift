import CryptoKit
import Foundation
import Security

/// Monedero de la app: tarjetas guardadas y pago con el móvil en tienda.
struct Monedero {

    /// Tarjetas guardadas en el llavero: AES-256-GCM (CryptoKit).
    func guardarTarjeta(_ datos: Data, clave: SymmetricKey) throws -> Data {
        try AES.GCM.seal(datos, using: clave).combined!
    }

    /// Clave híbrida del dispositivo para firmar los pagos: Ed25519 + ML-DSA-65 (FIPS 204).
    /// Ambas firmas deben verificarse en el receptor; se elimina P-256 (vulnerable ante Shor).
    struct ClaveDispositivoHibrida {
        let clasica: Curve25519.Signing.PrivateKey
        let postCuantica: MLDSA65.PrivateKey

        func firmar(_ datos: Data) throws -> (clasica: Data, postCuantica: Data) {
            (try clasica.signature(for: datos), try postCuantica.signature(for: datos))
        }
    }

    func claveDispositivo() throws -> ClaveDispositivoHibrida {
        ClaveDispositivoHibrida(clasica: Curve25519.Signing.PrivateKey(),
                                postCuantica: try MLDSA65.PrivateKey())
    }

    /// Clave del canal antiguo con el TPV (2018): RSA-1024 en el llavero.
    func claveTpvAntiguo() -> SecKey? {
        let atributos: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 1024,
        ]
        var error: Unmanaged<CFError>?
        return SecKeyCreateRandomKey(atributos as CFDictionary, &error)
    }

    /// Firma del recibo para el TPV antiguo: PKCS#1 v1.5 con SHA-1.
    func firmarReciboAntiguo(_ recibo: Data, clave: SecKey) -> Data? {
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

    /// Huella del ticket para la caché: MD5 (Insecure).
    func huellaTicket(_ ticket: Data) -> Insecure.MD5Digest {
        Insecure.MD5.hash(data: ticket)
    }

    /// Identificador del dispositivo: SHA-1.
    func idDispositivo(_ datos: Data) -> Insecure.SHA1Digest {
        Insecure.SHA1.hash(data: datos)
    }
}
