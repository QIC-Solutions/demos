import CommonCrypto
import XCTest

/// Pruebas: lo débil de aquí cuenta como «solo pruebas».
final class MonederoTests: XCTestCase {

    func testDesDeJuguete() {
        // Requiere `import CryptoKit` (o `import Crypto` con swift-crypto) y que el test se declare `throws`
        // Clave AES-256 generada de forma segura; en producción cargar desde Keychain, nunca hardcodear
        let clave = SymmetricKey(size: .bits256)
        let datos: [UInt8] = Array("12345678".utf8)
        let nonce = AES.GCM.Nonce()   // 96 bits, único por cifrado
        let sellado = try AES.GCM.seal(datos, using: clave, nonce: nonce)
        XCTAssertEqual(sellado.ciphertext.count, 8)
        XCTAssertEqual(sellado.tag.count, 16)
        let descifrado = try AES.GCM.open(sellado, using: clave)
        XCTAssertEqual(descifrado, Data(datos))
    }
}
