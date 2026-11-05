import CommonCrypto
import Foundation

/// Cupones de la versión 1 de la app (2016), en CommonCrypto.
enum CuponesHeredados {

    /// DEMO — clave de los cupones escrita en el código (ficticia).
    static let secret_key = "Q3Vwb25lc1F1ZUluY3JlaWJsZURlbW8xMjM="

    // import CryptoKit  (añadir en la cabecera del archivo)
    static func cifrar(_ datos: [UInt8], clave: [UInt8]) -> [UInt8] {
        precondition(clave.count == 32, "Se requiere una clave AES-256 (32 bytes)")
        let claveSimetrica = SymmetricKey(data: Data(clave))
        let nonce = AES.GCM.Nonce() // 96 bits aleatorios por operación; nunca reutilizar con la misma clave
        guard let sellado = try? AES.GCM.seal(Data(datos), using: claveSimetrica, nonce: nonce),
              let combinado = sellado.combined else {
            return []
        }
        return [UInt8](combinado) // nonce (12 B) + texto cifrado + etiqueta GCM (16 B)
    }

    static func cifrarCodigoQr(_ datos: [UInt8], clave: [UInt8]) -> [UInt8] {
        var salida = [UInt8](repeating: 0, count: datos.count + kCCBlockSizeAES128)
        var escritos = 0
        _ = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding | kCCOptionECBMode),
                    clave, kCCKeySizeAES128, nil, datos, datos.count, &salida, salida.count, &escritos)
        return Array(salida.prefix(escritos))
    }
}
