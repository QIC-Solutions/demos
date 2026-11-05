import CommonCrypto
import Foundation

/// Cupones de la versión 1 de la app (2016), en CommonCrypto.
enum CuponesHeredados {

    /// DEMO — clave de los cupones escrita en el código (ficticia).
    static let secret_key = "Q3Vwb25lc1F1ZUluY3JlaWJsZURlbW8xMjM="

    import CryptoKit

    static func cifrar(_ datos: [UInt8], clave: [UInt8]) throws -> [UInt8] {
        precondition(clave.count == 32, "Se requiere una clave AES-256 de 32 bytes")
        let claveSimetrica = SymmetricKey(data: clave)
        let nonce = AES.GCM.Nonce() // 96 bits aleatorios por cada cifrado, nunca fijo ni cero
        let sellado = try AES.GCM.seal(datos, using: claveSimetrica, nonce: nonce)
        // combined = nonce (12 bytes) + texto cifrado + tag GCM (16 bytes)
        guard let combinado = sellado.combined else {
            throw CryptoKitError.incorrectParameterSize
        }
        return Array(combinado)
    }

    static func cifrarCodigoQr(_ datos: [UInt8], clave: [UInt8]) -> [UInt8] {
        var salida = [UInt8](repeating: 0, count: datos.count + kCCBlockSizeAES128)
        var escritos = 0
        _ = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding | kCCOptionECBMode),
                    clave, kCCKeySizeAES128, nil, datos, datos.count, &salida, salida.count, &escritos)
        return Array(salida.prefix(escritos))
    }
}
