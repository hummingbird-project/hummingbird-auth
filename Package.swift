// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "hummingbird-auth",
    platforms: [.macOS(.v10_15), .iOS(.v12), .tvOS(.v12)],
    products: [
        .library(name: "HummingbirdAuth", targets: ["HummingbirdAuth"]),
        .library(name: "HummingbirdAuthXCT", targets: ["HummingbirdAuthXCT"]),
    ],
    dependencies: [
        .package(url: "https://github.com/hummingbird-project/hummingbird.git", from: "1.0.0-alpha"),
        .package(url: "https://github.com/apple/swift-crypto.git", "1.0.0"..<"3.0.0"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.33.0"),
        .package(url: "https://github.com/swift-extras/swift-extras-base64.git", .upToNextMinor(from: "0.7.0")),
    ],
    targets: [
        .target(name: "HummingbirdAuth", dependencies: [
            .byName(name: "CBcrypt"),
            .product(name: "Crypto", package: "swift-crypto"),
            .product(name: "ExtrasBase64", package: "swift-extras-base64"),
            .product(name: "Hummingbird", package: "hummingbird"),
            .product(name: "HummingbirdFoundation", package: "hummingbird"),
        ]),
        .target(name: "HummingbirdAuthXCT", dependencies: [
            .byName(name: "HummingbirdAuth"),
            .product(name: "HummingbirdXCT", package: "hummingbird"),
        ]),
        .target(name: "CBcrypt", dependencies: []),
        .testTarget(name: "HummingbirdAuthTests", dependencies: [
            .byName(name: "HummingbirdAuth"),
            .byName(name: "HummingbirdAuthXCT"),
            .product(name: "HummingbirdXCT", package: "hummingbird"),
            .product(name: "NIOPosix", package: "swift-nio"),
        ]),
    ]
)
