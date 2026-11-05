import CommonCrypto
import XCTest

/// Pruebas: lo débil de aquí cuenta como «solo pruebas».
final class MonederoTests: XCTestCase {

    func testDesDeJuguete() {
        // import CryptoKit (sustituye CommonCrypto); el método de test debe declararse `throws`
        let clave = SymmetricKey(size: .bits256)          // 256 bits, generada de forma segura
        let datos = Data("12345678".utf8)
        let sellado = try AES.GCM.seal(datos, using: clave) // AES-256-GCM: cifrado autenticado
        let abierto = try AES.GCM.open(sellado, using: clave)
        XCTAssertEqual(sellado.ciphertext.count, 8)
        XCTAssertEqual(sellado.tag.count, 16)
        XCTAssertEqual(abierto, datos)
    }
}
