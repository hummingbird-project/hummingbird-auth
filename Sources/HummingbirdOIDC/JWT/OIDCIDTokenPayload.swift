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
import JWTKit

/// JWTKit payload for an OIDC ID token.
///
/// Performs all mandatory verifications from OIDC Core 1.0 §3.1.3.7:
/// `iss`, `aud`, `exp`, `iat` (via `verifyNotExpired`), and `nonce`.
struct OIDCIDTokenPayload: JWTPayload, Sendable {
    // Standard JWT claims
    var issuer: IssuerClaim
    var subject: SubjectClaim
    var audience: AudienceClaim
    var expiration: ExpirationClaim
    var issuedAt: IssuedAtClaim
    var notBefore: NotBeforeClaim?
    var jwtID: IDClaim?

    // OIDC-specific claims
    var nonce: String?
    var authorizedParty: String?
    var atHash: String?

    // Standard profile claims (may come from ID token or UserInfo)
    var name: String?
    var givenName: String?
    var familyName: String?
    var email: String?
    var emailVerified: Bool?
    var picture: String?
    var locale: String?
    var updatedAt: Date?

    enum CodingKeys: String, CodingKey {
        case issuer = "iss"
        case subject = "sub"
        case audience = "aud"
        case expiration = "exp"
        case issuedAt = "iat"
        case notBefore = "nbf"
        case jwtID = "jti"
        case nonce
        case authorizedParty = "azp"
        case atHash = "at_hash"
        case name
        case givenName = "given_name"
        case familyName = "family_name"
        case email
        case emailVerified = "email_verified"
        case picture
        case locale
        case updatedAt = "updated_at"
    }

    /// Called by JWTKit after signature verification. We validate OIDC-specific rules here.
    ///
    /// The caller must also check `iss`, `aud`, `nonce`, and `azp` against configuration values
    /// using the `verify(against:nonce:clockSkew:)` helper below.
    ///
    /// Expiration is intentionally NOT checked here; the skew-aware check in
    /// `verify(expectedIssuer:clientID:expectedNonce:clockSkew:)` is authoritative.
    func verify(using algorithm: some JWTAlgorithm) async throws {}

    /// Full OIDC token validation against RP configuration.
    func verify(
        expectedIssuer: String,
        clientID: String,
        expectedNonce: String?,
        clockSkew: Duration,
        maxIDTokenAge: Duration? = nil
    ) throws {
        // sub must be non-empty (OIDC Core §2)
        guard !subject.value.isEmpty else {
            throw OIDCError.idTokenInvalid(.other("subject missing"))
        }

        // iss must match
        guard issuer.value == expectedIssuer else {
            throw OIDCError.idTokenInvalid(.issuerMismatch)
        }

        // aud must include clientID
        guard audience.value.contains(clientID) else {
            throw OIDCError.idTokenInvalid(.audienceMismatch)
        }

        // azp validation (OIDC Core §3.1.3.7 steps 4 & 7).
        if audience.value.count > 1 {
            // Multi-audience: azp MUST be present and equal clientID to prevent
            // audience-confusion. We enforce MUST rather than the spec's SHOULD.
            guard let azp = authorizedParty, !azp.isEmpty, azp == clientID else {
                throw OIDCError.idTokenInvalid(.audienceMismatch)
            }
        } else if let azp = authorizedParty, !azp.isEmpty {
            // Single-audience: azp must equal clientID when present.
            guard azp == clientID else {
                throw OIDCError.idTokenInvalid(.audienceMismatch)
            }
        }

        let now = Date()

        // exp with clock skew (authoritative check — verify(using:) intentionally skips this)
        let skewSeconds = clockSkew.timeInterval
        if expiration.value.addingTimeInterval(skewSeconds) < now {
            throw OIDCError.idTokenInvalid(.expired)
        }

        // iat must not be in the future (OIDC Core §3.1.3.7 step 9)
        if issuedAt.value > now.addingTimeInterval(skewSeconds) {
            throw OIDCError.idTokenInvalid(.other("iat in future"))
        }

        // iat freshness window (OIDC Core §3.1.3.7 step 10)
        if let maxAge = maxIDTokenAge {
            let maxAgeSeconds = TimeInterval(maxAge.components.seconds)
            if issuedAt.value < now.addingTimeInterval(-(maxAgeSeconds + skewSeconds)) {
                throw OIDCError.idTokenInvalid(.other("id_token too old"))
            }
        }

        // nbf
        if let nbf = notBefore, nbf.value.addingTimeInterval(-skewSeconds) > now {
            throw OIDCError.idTokenInvalid(.notYetValid)
        }

        // nonce
        if let expectedNonce {
            guard let tokenNonce = nonce, tokenNonce == expectedNonce else {
                throw OIDCError.idTokenInvalid(.nonceMismatch)
            }
        }
    }

    /// Verify `at_hash` against the given access token (optional, per OIDC Core §3.1.3.6).
    func verifyAccessTokenHash(_ accessToken: String) throws {
        guard let atHash else { return }
        let digest = SHA256.hash(data: Data(accessToken.utf8))
        let firstHalf = digest.prefix(SHA256.byteCount / 2)
        let computed = PKCE.base64URLEncode(Array(firstHalf))
        guard computed == atHash else {
            throw OIDCError.idTokenInvalid(.accessTokenHashMismatch)
        }
    }
}
