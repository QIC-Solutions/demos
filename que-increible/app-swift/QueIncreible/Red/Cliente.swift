import Foundation
import Network

/// Cliente HTTP de la app.
final class Cliente {

    /// Configuración por defecto: TLS 1.2 como mínimo.
    func sesion() -> URLSession {
        let configuracion = URLSessionConfiguration.default
        configuracion.tlsMinimumSupportedProtocolVersion = .TLSv12
        return URLSession(configuration: configuracion)
    }

    /// El servidor de los quioscos de tienda (2015) solo habla TLS 1.0.
    func sesionQuioscos() -> URLSession {
        let configuracion = URLSessionConfiguration.ephemeral
        configuracion.tlsMinimumSupportedProtocolVersion = .TLSv10
        return URLSession(configuration: configuracion)
    }
}
