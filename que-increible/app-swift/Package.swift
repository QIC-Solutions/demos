// swift-tools-version:6.0
// App iOS de clientes de Que Increible Compañia SL (empresa ficticia de demo).
import PackageDescription

let package = Package(
    name: "QueIncreible",
    platforms: [.iOS(.v26)],
    products: [.library(name: "QueIncreible", targets: ["QueIncreible"])],
    targets: [
        .target(name: "QueIncreible", path: "QueIncreible"),
        .testTarget(name: "QueIncreibleTests", dependencies: ["QueIncreible"], path: "tests/QueIncreibleTests"),
    ]
)
