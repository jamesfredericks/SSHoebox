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
        // Using GRDB.swift with SQLCipher support
        .package(url: "https://github.com/groue/GRDB.swift.git", from: "6.29.3"), 
    ],
    targets: [
        .target(
            name: "SSHoeboxCore",
            dependencies: [
                .product(name: "GRDB", package: "GRDB.swift"),
            ],
            path: "Sources/Core"
        ),
        .executableTarget(
            name: "SSHoeboxApp",
            dependencies: [
                "SSHoeboxCore"
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
