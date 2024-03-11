// swift-tools-version:5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "hummingbird-auth",
    platforms: [.macOS(.v14), .iOS(.v17), .tvOS(.v17)],
    products: [
        .library(name: "HummingbirdAuth", targets: ["HummingbirdAuth"]),
        .library(name: "HummingbirdAuthTesting", targets: ["HummingbirdAuthTesting"]),
    ],
    dependencies: [
        .package(url: "https://github.com/hummingbird-project/hummingbird.git", branch: "main"),
        .package(url: "https://github.com/apple/swift-crypto.git", "1.0.0"..<"4.0.0"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.63.0"),
        .package(url: "https://github.com/swift-extras/swift-extras-base64.git", .upToNextMinor(from: "0.7.0")),
    ],
    targets: [
        .target(name: "HummingbirdAuth", dependencies: [
            .byName(name: "CBcrypt"),
            .product(name: "Crypto", package: "swift-crypto"),
            .product(name: "ExtrasBase64", package: "swift-extras-base64"),
            .product(name: "Hummingbird", package: "hummingbird"),
        ]),
        .target(name: "HummingbirdAuthTesting", dependencies: [
            .byName(name: "HummingbirdAuth"),
            .product(name: "HummingbirdTesting", package: "hummingbird"),
        ]),
        .target(name: "CBcrypt", dependencies: []),
        .testTarget(name: "HummingbirdAuthTests", dependencies: [
            .byName(name: "HummingbirdAuth"),
            .byName(name: "HummingbirdAuthTesting"),
            .product(name: "HummingbirdTesting", package: "hummingbird"),
            .product(name: "NIOPosix", package: "swift-nio"),
        ]),
    ]
)
