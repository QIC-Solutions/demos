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
            // La generación automática no estuvo disponible. Aplicar la recomendación PQC indicada sobre el código detectado.
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
    // La generación automática no estuvo disponible. Aplicar la recomendación PQC indicada sobre el código detectado.
        Insecure.SHA1.hash(data: datos)
    }
}
