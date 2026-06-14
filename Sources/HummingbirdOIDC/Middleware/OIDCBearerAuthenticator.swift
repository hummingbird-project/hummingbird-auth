//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import Hummingbird
import HummingbirdAuth
import Logging

/// Authenticates requests by verifying a Bearer ID token in `Authorization: Bearer <token>`.
///
/// **Scope of use.** OIDC Core §2 specifies that ID tokens are credentials issued *to* the
/// Relying Party (RP) — their `aud` claim names the RP's `client_id`.  This middleware is
/// therefore only appropriate when the server receiving the request **is** the RP (i.e., the
/// same application that completed the authorization-code flow).  In that narrow case the
/// server can use the ID token as a first-party session credential.
///
/// **Do not use** this middleware in a resource server that is a *different* application
/// from the one that obtained the token.  For resource-server authentication, prefer:
/// - **RFC 9068 JWT access tokens** (structured access tokens the AS issues with `aud`
///   set to the resource server), or
/// - **Token introspection** (RFC 7662) — ask the AS at runtime whether the presented
///   token is valid and active.
///
/// ```swift
/// // Only valid when this server is the RP that originally obtained the token:
/// router.group()
///     .add(middleware: OIDCBearerAuthenticator(oidc: oidc))
///     .get("/me") { _, ctx in try ctx.requireIdentity() }
/// ```
public struct OIDCBearerAuthenticator<Context: AuthRequestContext>: AuthenticatorMiddleware
where Context.Identity == OIDCIdentity {
    public typealias Identity = OIDCIdentity

    let oidc: OIDC

    public init(oidc: OIDC) {
        self.oidc = oidc
    }

    public func authenticate(request: Request, context: Context) async throws -> OIDCIdentity? {
        guard let bearer = request.headers.bearer else { return nil }

        do {
            let metadata = try await oidc.resolveMetadata()
            let verifier = oidc.resolveVerifier(metadata: metadata)
            let payload = try await verifier.verify(
                idToken: bearer.token,
                expectedIssuer: oidc.configuration.issuer,
                clientID: oidc.configuration.clientID,
                expectedNonce: nil,
                clockSkew: oidc.configuration.clockSkew
            )
            let claims = OIDCClaims(
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
            return OIDCIdentity(
                subject: payload.subject.value,
                issuer: payload.issuer.value,
                idToken: bearer.token,
                claims: claims,
                accessToken: nil,
                refreshToken: nil,
                accessTokenExpiresAt: nil
            )
        } catch {
            context.logger.debug("OIDC bearer authentication failed", metadata: ["error": "\(error)"])
            return nil
        }
    }
}
