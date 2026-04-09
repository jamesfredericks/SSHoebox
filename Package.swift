// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SSHoebox",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(
            name: "SSHoebox",
            targets: ["SSHoeboxApp"]),
    ],
    dependencies: [
        // GRDB fork with SQLCipher pre-enabled (SQLITE_HAS_CODEC compiled into the module)
        .package(url: "https://github.com/mezhevikin/GRDB.SQLCipher.swift.git", revision: "2319bce6657900130cf1e1e95779f2dcfeeb85b0"),
        // Terminal emulator UI
        .package(url: "https://github.com/migueldeicaza/SwiftTerm.git", from: "1.2.0"),
        // SSH protocol client
        .package(path: "Vendor/Citadel"),
    ],
    targets: [
        .target(
            name: "SSHoeboxCore",
            dependencies: [
                .product(name: "GRDB", package: "GRDB.SQLCipher.swift"),
                .product(name: "Citadel", package: "Citadel"),
            ],
            path: "Sources/Core"
        ),
        .executableTarget(
            name: "SSHoeboxApp",
            dependencies: [
                "SSHoeboxCore",
                .product(name: "SwiftTerm", package: "SwiftTerm"),
            ],
            path: "Sources/SSHoeboxApp", resources: [.process("Resources")]
        ),
        .testTarget(
            name: "SSHoeboxTests",
            dependencies: ["SSHoeboxCore"],
            path: "Tests"
        ),
    ]
)
