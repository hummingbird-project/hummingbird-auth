//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import AsyncHTTPClient
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Hummingbird
import HummingbirdAuth
import Logging
import NIOConcurrencyHelpers

/// Façade that owns configuration, shared infrastructure, and produces handlers/middleware.
///
/// ```swift
/// let oidc = OIDC(
///     configuration: config,
///     stateStore: PersistDriverStateStore(persist),
///     httpClient: .shared
/// )
/// router.get("/auth/login", use: oidc.loginHandler)
/// router.get("/auth/callback", use: oidc.callbackHandler)
/// router.post("/auth/logout", use: oidc.logoutHandler)
/// ```
public struct OIDC: Sendable {
    let configuration: OIDCConfiguration
    let stateStore: any OIDCStateStore
    let httpClient: HTTPClient
    let logger: Logger

    // MARK: - Provider mode

    /// Holds the mode-specific infrastructure, making the mutual exclusion
    /// of `.discovered` vs `.static` fields structural rather than implicit.
    private enum ProviderMode: Sendable {
        case discovered(client: OIDCDiscoveryClient, verifierCache: DiscoveredVerifierCache)
        case `static`(metadata: OIDCProviderMetadata, verifier: JWTVerifier)
    }

    /// Lazily creates and caches the `JWTVerifier` (and its `JWKSCache`) in
    /// `.discovered` mode. `OIDC` is a `Sendable` value type, so mutable state
    /// lives in this reference type; all copies share the same instance.
    private final class DiscoveredVerifierCache: Sendable {
        // Keyed by jwks_uri so a URL rotation gets a fresh JWKSCache while the old
        // URL's verifier is still served to in-flight requests that haven't refreshed yet.
        private let _cached: NIOLockedValueBox<[String: JWTVerifier]> = .init([:])
        let configuration: OIDCConfiguration
        let httpClient: HTTPClient
        let logger: Logging.Logger

        init(configuration: OIDCConfiguration, httpClient: HTTPClient, logger: Logging.Logger) {
            self.configuration = configuration
            self.httpClient = httpClient
            self.logger = logger
        }

        func verifier(for metadata: OIDCProviderMetadata) -> JWTVerifier {
            _cached.withLockedValue { cache in
                if let existing = cache[metadata.jwksURI] { return existing }
                let jwksCache = JWKSCache(
                    jwksURL: metadata.jwksURI,
                    cacheTTL: configuration.jwksCacheTTL,
                    httpClient: httpClient,
                    logger: logger
                )
                let new = JWTVerifier(
                    jwksCache: jwksCache,
                    logger: logger,
                    allowedAlgorithms: [configuration.idTokenSignedResponseAlg]
                )
                cache[metadata.jwksURI] = new
                return new
            }
        }
    }

    private let providerMode: ProviderMode

    public init(
        configuration: OIDCConfiguration,
        stateStore: any OIDCStateStore,
        httpClient: HTTPClient = .shared,
        logger: Logger = Logger(label: "hummingbird-oidc")
    ) {
        self.configuration = configuration
        self.stateStore = stateStore
        self.httpClient = httpClient
        self.logger = logger

        switch configuration.providerSource {
        case .discovered:
            let discovery = OIDCDiscoveryClient(
                issuer: configuration.issuer,
                cacheTTL: configuration.discoveryCacheTTL,
                httpClient: httpClient,
                logger: logger
            )
            self.providerMode = .discovered(
                client: discovery,
                verifierCache: DiscoveredVerifierCache(
                    configuration: configuration,
                    httpClient: httpClient,
                    logger: logger
                )
            )
        case .static(let metadata):
            let cache = JWKSCache(
                jwksURL: metadata.jwksURI,
                cacheTTL: configuration.jwksCacheTTL,
                httpClient: httpClient,
                logger: logger
            )
            self.providerMode = .static(
                metadata: metadata,
                verifier: JWTVerifier(
                    jwksCache: cache,
                    logger: logger,
                    allowedAlgorithms: [configuration.idTokenSignedResponseAlg]
                )
            )
        }
    }

    // MARK: - Internal helpers

    func resolveMetadata() async throws -> OIDCProviderMetadata {
        // OIDC Core §3.1.2.1: the "openid" scope is required for ID token issuance.
        guard configuration.scopes.contains("openid") else {
            throw OIDCError.configurationError(reason: "scopes must include \"openid\" (OIDC Core §3.1.2.1)")
        }
        let metadata: OIDCProviderMetadata
        switch providerMode {
        case .discovered(let client, _):
            metadata = try await client.metadata()
        case .static(let m, _):
            metadata = m
        }
        if !configuration.allowInsecureTransport {
            try validateEndpointURLs(metadata: metadata)
        }
        let alg = configuration.idTokenSignedResponseAlg
        if !metadata.idTokenSigningAlgValuesSupported.contains(alg) {
            throw OIDCError.configurationError(
                reason: "idTokenSignedResponseAlg \"\(alg)\" is not in provider's idTokenSigningAlgValuesSupported \(metadata.idTokenSigningAlgValuesSupported)"
            )
        }
        return metadata
    }

    private func validateEndpointURLs(metadata: OIDCProviderMetadata) throws {
        func requireHTTPS(_ name: String, _ url: String) throws {
            guard url.hasPrefix("https://") else {
                throw OIDCError.invalidProviderMetadata(reason: "\(name) must use HTTPS (OIDC Core §16.17)")
            }
        }
        try requireHTTPS("issuer", configuration.issuer)
        try requireHTTPS("authorization_endpoint", metadata.authorizationEndpoint)
        try requireHTTPS("token_endpoint", metadata.tokenEndpoint)
        try requireHTTPS("jwks_uri", metadata.jwksURI)
        if let url = metadata.userInfoEndpoint { try requireHTTPS("userinfo_endpoint", url) }
        if let url = metadata.endSessionEndpoint { try requireHTTPS("end_session_endpoint", url) }
    }

    func resolveVerifier(metadata: OIDCProviderMetadata) -> JWTVerifier {
        switch providerMode {
        case .static(_, let verifier):
            return verifier
        case .discovered(_, let cache):
            return cache.verifier(for: metadata)
        }
    }

    // MARK: - Route handlers
    //
    // Use these directly as route handlers:
    //   router.get("/auth/login", use: oidc.loginHandler)
    //   router.get("/auth/callback", use: oidc.callbackSessionHandler)
    //   router.post("/auth/logout", use: oidc.logoutHandler)

    /// Redirects the user to the IdP's authorization endpoint.
    public func loginHandler(_ request: Request, _ context: some RequestContext) async throws -> Response {
        try await handleLogin(request: request)
    }

    /// Callback handler: exchanges code for tokens, writes the identity into the session, and
    /// redirects to `postLoginRedirectPath` (or the per-login `returnTo` path if one was captured).
    ///
    /// Requires `SessionMiddleware<OIDCSessionData>` earlier in the middleware chain.
    public func callbackSessionHandler<Context: SessionRequestContext>(
        _ request: Request,
        _ context: Context
    ) async throws -> Response where Context.Session == OIDCSessionData {
        let (identity, authState) = try await processCallback(request: request)
        context.sessions.setSession(OIDCSessionData(from: identity))
        let redirectPath = authState.returnTo ?? configuration.postLoginRedirectPath
        return Response(
            status: .seeOther,
            headers: [.location: redirectPath]
        )
    }

    /// Clears the local session and redirects to the IdP's end-session endpoint.
    ///
    /// Passes `id_token_hint` so the IdP can identify the session being terminated.
    /// Requires `SessionMiddleware<OIDCSessionData>` earlier in the middleware chain.
    public func logoutHandler<Context: SessionRequestContext>(
        _ request: Request,
        _ context: Context
    ) async throws -> Response where Context.Session == OIDCSessionData {
        let idToken = context.sessions.session?.idToken
        context.sessions.clearSession()
        return try await handleLogout(idTokenHint: idToken)
    }

    // MARK: - Private flow methods

    func handleLogin(request: Request) async throws -> Response {
        let metadata = try await resolveMetadata()

        let pkce = PKCE()
        let state = generateRandomToken()
        let nonce = generateRandomToken()

        // Capture a validated `returnTo` path from the query string, if present.
        let returnTo = OIDC.validatedReturnTo(
            request.uri.queryParameters.get("returnTo").map { String($0) }
        )

        let entry = OIDCAuthRequestState(
            state: state,
            nonce: nonce,
            pkceVerifier: pkce.verifier,
            returnTo: returnTo
        )
        try await stateStore.save(entry, expiresIn: .seconds(60 * 10))

        guard var components = URLComponents(string: metadata.authorizationEndpoint) else {
            throw HTTPError(.badGateway)
        }
        components.queryItems = [
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "client_id", value: configuration.clientID),
            URLQueryItem(name: "redirect_uri", value: configuration.redirectURI),
            URLQueryItem(name: "scope", value: configuration.scopes.joined(separator: " ")),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "nonce", value: nonce),
            URLQueryItem(name: "code_challenge", value: pkce.challenge),
            URLQueryItem(name: "code_challenge_method", value: pkce.challengeMethod),
        ]

        guard let authURL = components.url?.absoluteString else {
            throw HTTPError(.internalServerError)
        }

        return Response(status: .found, headers: [.location: authURL])
    }

    /// Processes an OIDC authorization callback: validates the state parameter, exchanges the
    /// code for tokens, and verifies the ID token.
    ///
    /// Returns both the resolved identity and the consumed auth-request state so callers can
    /// read the `returnTo` field without a second state-store lookup.
    func processCallback(request: Request) async throws -> (OIDCIdentity, OIDCAuthRequestState) {
        let params = request.uri.queryParameters

        // Validate state first on ALL paths (success and error) — RFC 6749 §4.1.2.1.
        guard let stateParam = params.get("state").map({ String($0) }) else {
            throw HTTPError(.badRequest)
        }
        guard let authState = try await stateStore.consume(state: stateParam) else {
            throw OIDCError.invalidState
        }

        // Provider-side error (state is now validated and consumed).
        if let error = params.get("error").map({ String($0) }) {
            let description = params.get("error_description").map { String($0) }
            throw OIDCError.providerError(code: error, description: description)
        }

        guard let code = params.get("code").map({ String($0) }) else {
            throw HTTPError(.badRequest)
        }

        let metadata = try await resolveMetadata()
        let tokenResponse = try await TokenExchange(
            configuration: configuration,
            httpClient: httpClient,
            logger: logger
        ).exchange(
            code: code,
            pkceVerifier: authState.pkceVerifier,
            tokenEndpointURL: metadata.tokenEndpoint
        )

        // Authorization-code flow always requires an id_token.
        guard let rawIDToken = tokenResponse.idToken else {
            throw OIDCError.providerError(code: "missing_id_token", description: "Token endpoint did not return an id_token")
        }

        let jwtVerifier = resolveVerifier(metadata: metadata)
        let payload = try await jwtVerifier.verify(
            idToken: rawIDToken,
            expectedIssuer: configuration.issuer,
            clientID: configuration.clientID,
            expectedNonce: authState.nonce,
            clockSkew: configuration.clockSkew,
            maxIDTokenAge: configuration.maxIDTokenAge
        )

        if let accessToken = tokenResponse.accessToken {
            try payload.verifyAccessTokenHash(accessToken)
        }

        // Fetch UserInfo if configured and we have an access token
        var claims = OIDCClaims(
            subject: payload.subject.value,
            name: payload.name,
            givenName: payload.givenName,
            familyName: payload.familyName,
            email: payload.email,
            emailVerified: payload.emailVerified,
            picture: payload.picture,
            locale: payload.locale,
            updatedAt: payload.updatedAt
        )
        if configuration.fetchUserInfo,
           let accessToken = tokenResponse.accessToken,
           let userInfoURL = metadata.userInfoEndpoint
        {
            let userInfoClaims = try await UserInfoClient(httpClient: httpClient)
                .fetch(userInfoURL: userInfoURL, accessToken: accessToken)
            // OIDC Core §5.3.2: if UserInfo returns sub it MUST match the ID token sub.
            if userInfoClaims.subject != payload.subject.value {
                throw OIDCError.idTokenInvalid(.other("UserInfo sub mismatch"))
            }
            claims = userInfoClaims
        }

        let expiresAt = tokenResponse.expiresIn.map { Date().addingTimeInterval(TimeInterval($0)) }
        let identity = OIDCIdentity(
            subject: payload.subject.value,
            issuer: payload.issuer.value,
            idToken: rawIDToken,
            claims: claims,
            accessToken: tokenResponse.accessToken,
            refreshToken: tokenResponse.refreshToken,
            accessTokenExpiresAt: expiresAt
        )
        return (identity, authState)
    }

    /// Exchanges a refresh token for a fresh set of tokens.
    ///
    /// Per OIDC Core, a refresh response may or may not include a new `id_token`.
    /// - If a new `id_token` is present it is fully verified (signature, iss, aud, exp, iat,
    ///   sub). Nonce validation is intentionally skipped because refresh responses do not
    ///   carry the original nonce.
    /// - If no new `id_token` is returned the `previousIdentity`'s token and claims are
    ///   reused. If `previousIdentity` is `nil` and there is no new `id_token`, throws
    ///   `OIDCError.providerError(code: "missing_id_token", ...)`.
    ///
    /// Per RFC 6749 §6, if the response includes a new `refresh_token` the old one is
    /// superseded; otherwise the supplied `refreshToken` value is preserved in the
    /// returned identity.
    public func refreshIdentity(
        refreshToken: String,
        previousIdentity: OIDCIdentity? = nil
    ) async throws -> OIDCIdentity {
        let metadata = try await resolveMetadata()
        let tokenResponse = try await TokenExchange(
            configuration: configuration,
            httpClient: httpClient,
            logger: logger
        ).refresh(
            refreshToken: refreshToken,
            tokenEndpointURL: metadata.tokenEndpoint
        )

        let resolvedIDToken: String
        let resolvedSubject: String
        let resolvedIssuer: String
        let resolvedClaims: OIDCClaims

        if let rawIDToken = tokenResponse.idToken {
            // Verify the new id_token (no nonce on the refresh path — OIDC Core allows omission).
            let jwtVerifier = resolveVerifier(metadata: metadata)
            let payload = try await jwtVerifier.verify(
                idToken: rawIDToken,
                expectedIssuer: configuration.issuer,
                clientID: configuration.clientID,
                expectedNonce: nil,
                clockSkew: configuration.clockSkew,
                maxIDTokenAge: configuration.maxIDTokenAge
            )
            // OIDC Core §12: sub and iss must not change across a refresh.
            if let previous = previousIdentity {
                guard payload.subject.value == previous.subject,
                      payload.issuer.value == previous.issuer
                else {
                    throw OIDCError.idTokenInvalid(.other("refresh sub/iss mismatch"))
                }
            }
            resolvedIDToken = rawIDToken
            resolvedSubject = payload.subject.value
            resolvedIssuer = payload.issuer.value
            resolvedClaims = OIDCClaims(
                subject: payload.subject.value,
                name: payload.name,
                givenName: payload.givenName,
                familyName: payload.familyName,
                email: payload.email,
                emailVerified: payload.emailVerified,
                picture: payload.picture,
                locale: payload.locale,
                updatedAt: payload.updatedAt
            )
        } else if let previous = previousIdentity {
            // No new id_token — reuse everything from the previous identity.
            resolvedIDToken = previous.idToken
            resolvedSubject = previous.subject
            resolvedIssuer = previous.issuer
            resolvedClaims = previous.claims
        } else {
            throw OIDCError.providerError(
                code: "missing_id_token",
                description: "Refresh response contained no id_token and no previousIdentity was supplied"
            )
        }

        // Per RFC 6749 §6: use the new refresh token if one was issued; otherwise keep the old one.
        let newRefreshToken = tokenResponse.refreshToken ?? refreshToken
        let expiresAt = tokenResponse.expiresIn.map { Date().addingTimeInterval(TimeInterval($0)) }

        return OIDCIdentity(
            subject: resolvedSubject,
            issuer: resolvedIssuer,
            idToken: resolvedIDToken,
            claims: resolvedClaims,
            accessToken: tokenResponse.accessToken,
            refreshToken: newRefreshToken,
            accessTokenExpiresAt: expiresAt
        )
    }

    func handleLogout(idTokenHint: String?) async throws -> Response {
        let endSessionEndpoint: String?
        do {
            endSessionEndpoint = try await resolveMetadata().endSessionEndpoint
        } catch {
            logger.warning(
                "OIDC logout: could not resolve provider metadata, skipping IdP redirect",
                metadata: ["error": "\(error)"]
            )
            endSessionEndpoint = nil
        }
        if let endSessionEndpoint,
           var components = URLComponents(string: endSessionEndpoint) {
            var queryItems: [URLQueryItem] = []
            if let hint = idTokenHint {
                queryItems.append(URLQueryItem(name: "id_token_hint", value: hint))
            }
            if let postLogout = configuration.postLogoutRedirectURI {
                queryItems.append(URLQueryItem(name: "post_logout_redirect_uri", value: postLogout))
            }
            if !queryItems.isEmpty {
                components.queryItems = queryItems
            }
            if let url = components.url?.absoluteString {
                return Response(status: .found, headers: [.location: url])
            }
        }
        return Response(status: .ok)
    }

    private func generateRandomToken() -> String {
        PKCE.base64URLEncode(secureRandomBytes(count: 32))
    }

    // MARK: - returnTo validation

    /// Validates that `rawValue` is a safe same-origin relative path.
    ///
    /// Acceptance rules (all must hold):
    /// - Non-nil and non-empty after percent-decoding.
    /// - Starts with exactly one `/` (rejects `//` protocol-relative URLs).
    /// - Does not contain `://` (rejects absolute URLs with any scheme).
    /// - Does not contain `\` (rejects backslash injection like `/\evil.com`).
    /// - Does not contain whitespace characters (paths must be URL-encoded; spaces
    ///   indicate an unencoded or injected value).
    ///
    /// If validation fails, returns `nil`. Never throws — a bad `returnTo` is a UX
    /// detail, not an auth failure.
    static func validatedReturnTo(_ rawValue: String?) -> String? {
        guard let raw = rawValue, !raw.isEmpty else { return nil }

        // Percent-decode so we evaluate the actual path characters.
        let decoded = raw.removingPercentEncoding ?? raw

        guard !decoded.isEmpty else { return nil }

        // Must start with exactly one '/'.
        guard decoded.hasPrefix("/") else { return nil }
        // Must NOT start with '//' (protocol-relative).
        if decoded.hasPrefix("//") { return nil }

        // Must not contain '://' (would indicate a scheme like https://).
        if decoded.contains("://") { return nil }

        // Must not contain backslashes (backslash injection).
        if decoded.contains("\\") { return nil }

        // Must not contain whitespace.
        if decoded.contains(where: { $0.isWhitespace }) { return nil }

        return decoded
    }
}
