//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

/// Decoded OpenID Connect Discovery document (RFC 8414 / OIDC Discovery 1.0).
///
/// Only fields used by this module are modelled; unknown fields are ignored.
public struct OIDCProviderMetadata: Codable, Sendable {
    /// Issuer identifier (must match the `iss` claim in ID tokens)
    public let issuer: String
    /// Authorization endpoint URL
    public let authorizationEndpoint: String
    /// Token endpoint URL
    public let tokenEndpoint: String
    /// JWKS endpoint URL
    public let jwksURI: String
    /// UserInfo endpoint URL (optional)
    public let userInfoEndpoint: String?
    /// End-session endpoint URL (optional, for RP-initiated logout)
    public let endSessionEndpoint: String?
    /// Supported response types
    public let responseTypesSupported: [String]
    /// Supported subject types (REQUIRED by OIDC Discovery 1.0 §3)
    public let subjectTypesSupported: [String]
    /// Supported ID token signing algorithms
    public let idTokenSigningAlgValuesSupported: [String]
    /// Supported scopes (optional, informational)
    public let scopesSupported: [String]?
    /// Supported token endpoint auth methods
    public let tokenEndpointAuthMethodsSupported: [String]?

    enum CodingKeys: String, CodingKey {
        case issuer
        case authorizationEndpoint = "authorization_endpoint"
        case tokenEndpoint = "token_endpoint"
        case jwksURI = "jwks_uri"
        case userInfoEndpoint = "userinfo_endpoint"
        case endSessionEndpoint = "end_session_endpoint"
        case responseTypesSupported = "response_types_supported"
        case subjectTypesSupported = "subject_types_supported"
        case idTokenSigningAlgValuesSupported = "id_token_signing_alg_values_supported"
        case scopesSupported = "scopes_supported"
        case tokenEndpointAuthMethodsSupported = "token_endpoint_auth_methods_supported"
    }

    public init(
        issuer: String,
        authorizationEndpoint: String,
        tokenEndpoint: String,
        jwksURI: String,
        userInfoEndpoint: String? = nil,
        endSessionEndpoint: String? = nil,
        responseTypesSupported: [String] = ["code"],
        subjectTypesSupported: [String]? = nil,  // nil → defaults to ["public"] for convenience
        idTokenSigningAlgValuesSupported: [String] = ["RS256"],
        scopesSupported: [String]? = nil,
        tokenEndpointAuthMethodsSupported: [String]? = nil
    ) {
        self.issuer = issuer
        self.authorizationEndpoint = authorizationEndpoint
        self.tokenEndpoint = tokenEndpoint
        self.jwksURI = jwksURI
        self.userInfoEndpoint = userInfoEndpoint
        self.endSessionEndpoint = endSessionEndpoint
        self.responseTypesSupported = responseTypesSupported
        self.subjectTypesSupported = subjectTypesSupported ?? ["public"]
        self.idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported
        self.scopesSupported = scopesSupported
        self.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported
    }
}
