//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import JWTKit
import Logging

/// Verifies OIDC ID tokens using a `JWKSCache` for key material.
///
/// On a `kid`-not-found error it triggers one JWKS refresh (key rotation support).
/// Rejects `alg=none` unconditionally.
/// When `allowedAlgorithms` is non-empty, rejects tokens whose JOSE header `alg`
/// is not in the list (prevents alg-confusion attacks, OIDC Core §3.1.3.7 step 7).
public struct JWTVerifier: Sendable {
    let jwksCache: JWKSCache
    let logger: Logger
    /// Algorithms the verifier will accept. Empty means no restriction (beyond rejecting `none`).
    let allowedAlgorithms: [String]

    public init(
        jwksCache: JWKSCache,
        logger: Logger = Logger(label: "hummingbird-oidc.jwt"),
        allowedAlgorithms: [String] = []
    ) {
        self.jwksCache = jwksCache
        self.logger = logger
        self.allowedAlgorithms = allowedAlgorithms
    }

    /// Verify and decode an ID token.
    ///
    /// - Parameters:
    ///   - idToken: The raw JWS string from the token response.
    ///   - expectedIssuer: Must match `iss` claim.
    ///   - clientID: Must appear in `aud` claim.
    ///   - expectedNonce: Must match `nonce` claim (pass nil to skip).
    ///   - clockSkew: Allowed leeway for `exp`/`nbf`.
    ///   - maxIDTokenAge: If set, rejects tokens whose `iat` is older than this window.
    func verify(
        idToken: String,
        expectedIssuer: String,
        clientID: String,
        expectedNonce: String?,
        clockSkew: Duration,
        maxIDTokenAge: Duration? = nil
    ) async throws -> OIDCIDTokenPayload {
        // Peek at the JOSE header to reject alg=none (and any disallowed alg) before fetching keys.
        let headerAlg = peekAlgorithm(token: idToken)
        guard let headerAlg, headerAlg.lowercased() != "none" else {
            throw OIDCError.idTokenInvalid(.unsupportedAlgorithm(headerAlg ?? "none"))
        }
        if !allowedAlgorithms.isEmpty {
            guard allowedAlgorithms.contains(headerAlg) else {
                throw OIDCError.idTokenInvalid(.unsupportedAlgorithm(headerAlg))
            }
        }
        let keys = try await jwksCache.keyCollection()

        let payload: OIDCIDTokenPayload
        do {
            payload = try await keys.verify(idToken, as: OIDCIDTokenPayload.self)
        } catch let jwtError as JWTError
          where jwtError.errorType == .unknownKID || jwtError.errorType == .noKeyProvided {
            // Unknown key — possibly a rotation. Refresh JWKS once and retry.
            logger.debug("JWT key not found, refreshing JWKS", metadata: ["kid": "\(String(describing: jwtError.kid))"])
            let refreshedKeys = try await jwksCache.keyCollection(forceRefresh: true)
            do {
                payload = try await refreshedKeys.verify(idToken, as: OIDCIDTokenPayload.self)
            } catch {
                // Wrap retry failure so callers always see OIDCError, not raw JWTKit error.
                throw OIDCError.idTokenInvalid(.signatureVerificationFailed)
            }
        } catch {
            // Bad signature, malformed token, etc. — wrap so callers always see OIDCError.
            throw OIDCError.idTokenInvalid(.signatureVerificationFailed)
        }

        try payload.verify(
            expectedIssuer: expectedIssuer,
            clientID: clientID,
            expectedNonce: expectedNonce,
            clockSkew: clockSkew,
            maxIDTokenAge: maxIDTokenAge
        )

        return payload
    }

    private func peekAlgorithm(token: String) -> String? {
        let parts = token.split(separator: ".", maxSplits: 1)
        guard let headerB64 = parts.first else { return nil }
        let padded = String(headerB64) + String(repeating: "=", count: (4 - headerB64.count % 4) % 4)
        let normalized = padded.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        guard let data = Data(base64Encoded: normalized),
              let header = try? JSONDecoder().decode(JOSEHeader.self, from: data)
        else { return nil }
        return header.alg
    }

    private struct JOSEHeader: Decodable {
        let alg: String?
    }
}
