import CommonCrypto
import Foundation

/// Cupones de la versión 1 de la app (2016), en CommonCrypto.
enum CuponesHeredados {

    /// DEMO — clave de los cupones escrita en el código (ficticia).
    static let secret_key = "Q3Vwb25lc1F1ZUluY3JlaWJsZURlbW8xMjM="

    static func cifrar(_ datos: [UInt8], clave: [UInt8]) -> [UInt8] {
        var salida = [UInt8](repeating: 0, count: datos.count + kCCBlockSize3DES)
        var escritos = 0
        let iv = [UInt8](repeating: 0, count: kCCBlockSize3DES)
        _ = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithm3DES), CCOptions(kCCOptionPKCS7Padding),
                    clave, kCCKeySize3DES, iv, datos, datos.count, &salida, salida.count, &escritos)
        return Array(salida.prefix(escritos))
    }

    static func cifrarCodigoQr(_ datos: [UInt8], clave: [UInt8]) -> [UInt8] {
        var salida = [UInt8](repeating: 0, count: datos.count + kCCBlockSizeAES128)
        var escritos = 0
        _ = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding | kCCOptionECBMode),
                    clave, kCCKeySizeAES128, nil, datos, datos.count, &salida, salida.count, &escritos)
        return Array(salida.prefix(escritos))
    }
}
