//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import Crypto
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Returns `count` cryptographically random bytes using the platform CSPRNG.
func secureRandomBytes(count: Int) -> [UInt8] {
    var rng = SystemRandomNumberGenerator()
    return (0..<count).map { _ in rng.next() }
}

/// PKCE (Proof Key for Code Exchange) generator per RFC 7636.
///
/// Uses S256 exclusively — `plain` is not supported.
public struct PKCE: Sendable {
    /// The high-entropy random verifier (kept secret, sent at token exchange)
    public let verifier: String
    /// The SHA-256 digest of the verifier, base64url-encoded (sent in /authorize)
    public let challenge: String

    /// Generate a fresh PKCE pair using a 32-byte random verifier.
    public init() {
        let bytes = secureRandomBytes(count: 32)
        self.verifier = Self.base64URLEncode(bytes)
        let digest = SHA256.hash(data: Data(verifier.utf8))
        self.challenge = Self.base64URLEncode(Array(digest))
    }

    /// The challenge method — always "S256".
    public var challengeMethod: String { "S256" }

    static func base64URLEncode(_ bytes: [UInt8]) -> String {
        Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
