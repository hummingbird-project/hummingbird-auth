//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

/// How the client authenticates to the token endpoint.
public enum OIDCClientAuthMethod: Sendable {
    /// HTTP Basic auth: client_id + client_secret in Authorization header (recommended)
    case clientSecretBasic
    /// client_id + client_secret in POST body
    case clientSecretPost
    /// No client secret (public client using PKCE)
    case none
}

/// Relying Party configuration for an OIDC Authorization Code + PKCE flow.
public struct OIDCConfiguration: Sendable {
    /// How to obtain provider metadata.
    public enum ProviderSource: Sendable {
        /// Fetch from `<issuer>/.well-known/openid-configuration`
        case discovered
        /// Use a pre-loaded metadata document (useful for testing or providers without discovery)
        case `static`(OIDCProviderMetadata)
    }

    /// OAuth 2.0 client identifier
    public var clientID: String
    /// Client secret (nil for public PKCE-only clients)
    public var clientSecret: String?
    /// Absolute URI of the callback route, e.g. "https://example.com/auth/callback"
    public var redirectURI: String
    /// Scopes to request (must include "openid")
    public var scopes: [String]
    /// Issuer identifier, used for `iss` validation and discovery URL
    public var issuer: String
    /// Where to obtain provider metadata
    public var providerSource: ProviderSource
    /// How to authenticate to the token endpoint
    public var tokenEndpointAuthMethod: OIDCClientAuthMethod
    /// If true, call the userinfo endpoint after a successful token exchange
    public var fetchUserInfo: Bool
    /// Maximum allowed clock skew when validating token timestamps
    public var clockSkew: Duration
    /// How long to cache JWKS responses
    public var jwksCacheTTL: Duration
    /// How long to cache the discovery document
    public var discoveryCacheTTL: Duration
    /// Post-login redirect URI (relative path or allowlisted absolute)
    public var postLoginRedirectPath: String
    /// URI to redirect to after logout (optional)
    public var postLogoutRedirectURI: String?
    /// The single signing algorithm the RP expects for ID tokens.
    ///
    /// Must appear in the provider's `id_token_signing_alg_values_supported` list.
    /// Tokens signed with any other algorithm are rejected (OIDC Core §3.1.3.7 step 7,
    /// §15.5.2). Default is `"RS256"`, which is the most widely supported algorithm.
    public var idTokenSignedResponseAlg: String
    /// When `true`, `http://` endpoints are permitted (OIDC Core §16.17 escape hatch).
    ///
    /// Never set this in production. Intended only for local development and testing.
    public var allowInsecureTransport: Bool
    /// Maximum age of an ID token's `iat` claim (OIDC Core §3.1.3.7 step 10).
    ///
    /// When set, tokens whose `iat` is older than this window (subject to `clockSkew`) are
    /// rejected. `nil` (the default) disables the check.
    public var maxIDTokenAge: Duration?

    public init(
        clientID: String,
        clientSecret: String? = nil,
        redirectURI: String,
        scopes: [String] = ["openid", "profile", "email"],
        issuer: String,
        providerSource: ProviderSource = .discovered,
        tokenEndpointAuthMethod: OIDCClientAuthMethod = .clientSecretBasic,
        fetchUserInfo: Bool = false,
        clockSkew: Duration = .seconds(60),
        jwksCacheTTL: Duration = .seconds(60 * 15),
        discoveryCacheTTL: Duration = .seconds(60 * 60 * 24),
        postLoginRedirectPath: String = "/",
        postLogoutRedirectURI: String? = nil,
        idTokenSignedResponseAlg: String = "RS256",
        allowInsecureTransport: Bool = false,
        maxIDTokenAge: Duration? = nil
    ) {
        self.clientID = clientID
        self.clientSecret = clientSecret
        self.redirectURI = redirectURI
        self.scopes = scopes
        self.issuer = issuer
        self.providerSource = providerSource
        self.tokenEndpointAuthMethod = tokenEndpointAuthMethod
        self.fetchUserInfo = fetchUserInfo
        self.clockSkew = clockSkew
        self.jwksCacheTTL = jwksCacheTTL
        self.discoveryCacheTTL = discoveryCacheTTL
        self.postLoginRedirectPath = postLoginRedirectPath
        self.postLogoutRedirectURI = postLogoutRedirectURI
        self.idTokenSignedResponseAlg = idTokenSignedResponseAlg
        self.allowInsecureTransport = allowInsecureTransport
        self.maxIDTokenAge = maxIDTokenAge
    }
}
