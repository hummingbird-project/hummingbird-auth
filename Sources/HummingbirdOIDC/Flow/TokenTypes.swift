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

/// Response from the token endpoint.
struct TokenResponse: Decodable, Sendable {
    let idToken: String?
    let accessToken: String?
    let refreshToken: String?
    let tokenType: String?
    let expiresIn: Int?
    let scope: String?

    enum CodingKeys: String, CodingKey {
        case idToken = "id_token"
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
        case scope
    }
}

/// Error response from the token endpoint.
struct TokenErrorResponse: Decodable, Sendable {
    let error: String
    let errorDescription: String?

    enum CodingKeys: String, CodingKey {
        case error
        case errorDescription = "error_description"
    }
}

/// Standard OIDC claims decoded from the ID token or UserInfo endpoint.
public struct OIDCClaims: Sendable, Codable {
    public let subject: String
    public let name: String?
    public let givenName: String?
    public let familyName: String?
    public let email: String?
    public let emailVerified: Bool?
    public let picture: String?
    public let locale: String?
    public let updatedAt: Date?

    enum CodingKeys: String, CodingKey {
        case subject = "sub"
        case name
        case givenName = "given_name"
        case familyName = "family_name"
        case email
        case emailVerified = "email_verified"
        case picture
        case locale
        case updatedAt = "updated_at"
    }
}

/// The authenticated identity produced after a successful OIDC flow.
public struct OIDCIdentity: Sendable, Codable {
    /// Subject identifier (`sub` claim)
    public let subject: String
    /// Issuer (`iss` claim)
    public let issuer: String
    /// The raw ID token JWS string
    public let idToken: String
    /// Standard profile/email claims
    public let claims: OIDCClaims
    /// Access token (if issued)
    public let accessToken: String?
    /// Refresh token (if issued)
    public let refreshToken: String?
    /// When the access token expires
    public let accessTokenExpiresAt: Date?

    public init(
        subject: String,
        issuer: String,
        idToken: String,
        claims: OIDCClaims,
        accessToken: String?,
        refreshToken: String?,
        accessTokenExpiresAt: Date?
    ) {
        self.subject = subject
        self.issuer = issuer
        self.idToken = idToken
        self.claims = claims
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.accessTokenExpiresAt = accessTokenExpiresAt
    }
}

extension OIDCIdentity {
    public init(from session: OIDCSessionData) {
        self.init(
            subject: session.subject,
            issuer: session.issuer,
            idToken: session.idToken,
            claims: session.claims,
            accessToken: session.accessToken,
            refreshToken: session.refreshToken,
            accessTokenExpiresAt: session.accessTokenExpiresAt
        )
    }
}

/// Data stored in the session after a successful OIDC login.
public struct OIDCSessionData: Sendable, Codable {
    public let subject: String
    public let issuer: String
    public let idToken: String
    public let claims: OIDCClaims
    public let accessToken: String?
    public let refreshToken: String?
    public let accessTokenExpiresAt: Date?

    public init(from identity: OIDCIdentity) {
        self.subject = identity.subject
        self.issuer = identity.issuer
        self.idToken = identity.idToken
        self.claims = identity.claims
        self.accessToken = identity.accessToken
        self.refreshToken = identity.refreshToken
        self.accessTokenExpiresAt = identity.accessTokenExpiresAt
    }
}
