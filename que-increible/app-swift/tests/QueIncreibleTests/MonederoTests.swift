import CommonCrypto
import XCTest

/// Pruebas: lo débil de aquí cuenta como «solo pruebas».
final class MonederoTests: XCTestCase {

    func testDesDeJuguete() {
        var salida = [UInt8](repeating: 0, count: 16)
        var escritos = 0
        let clave: [UInt8] = Array("8bytes!!".utf8)
        let datos: [UInt8] = Array("12345678".utf8)
        _ = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmDES), CCOptions(kCCOptionECBMode),
                    clave, kCCKeySizeDES, nil, datos, datos.count, &salida, salida.count, &escritos)
        XCTAssertEqual(escritos, 8)
    }
}
