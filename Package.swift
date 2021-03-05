// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "hummingbird-auth",
    platforms: [.macOS(.v10_15)],
    products: [
        .library(name: "HummingbirdAuth", targets: ["HummingbirdAuth"]),
    ],
    dependencies: [
        .package(url: "https://github.com/hummingbird-project/hummingbird.git", from: "0.5.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "1.0.0"),
        .package(url: "https://github.com/swift-extras/swift-extras-base64.git", from: "0.5.0"),
    ],
    targets: [
        .target(name: "HummingbirdAuth", dependencies: [
            .byName(name: "CBcrypt"),
            .product(name: "Crypto", package: "swift-crypto"),
            .product(name: "ExtrasBase64", package: "swift-extras-base64"),
            .product(name: "Hummingbird", package: "hummingbird"),
        ]),
        .target(name: "CBcrypt", dependencies: []),
        .testTarget(name: "HummingbirdAuthTests", dependencies: [
            .byName(name: "HummingbirdAuth"),
            .product(name: "HummingbirdXCT", package: "hummingbird"),
        ]),
    ]
)
