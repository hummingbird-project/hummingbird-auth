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
import Hummingbird
import HummingbirdAuth
import Logging

/// Authenticates requests by reading `OIDCSessionData` from the session.
///
/// Must be placed after `SessionMiddleware` in the middleware chain, following the same
/// pattern as `SessionAuthenticator` in HummingbirdAuth.
///
/// ```swift
/// router.addMiddleware {
///     SessionMiddleware(storage: persist)
/// }
/// router.group()
///     .add(middleware: OIDCSessionAuthenticator(oidc: oidc))
///     .get("/me") { _, ctx in try ctx.requireIdentity() }
/// ```
///
/// Pass `autoRefresh: true` to automatically exchange an expired access token for a new
/// one using the stored refresh token.  On success the session is updated and the new
/// identity is returned.  On failure (no refresh token, exchange error) the middleware
/// falls through to `nil`, which causes the caller to redirect to login as usual.
public struct OIDCSessionAuthenticator<
    Context: AuthRequestContext & SessionRequestContext
>: AuthenticatorMiddleware
where Context.Identity == OIDCIdentity, Context.Session == OIDCSessionData {
    public typealias Identity = OIDCIdentity

    @usableFromInline
    let configuration: OIDCConfiguration
    @usableFromInline
    let oidc: OIDC
    @usableFromInline
    let autoRefresh: Bool

    public init(oidc: OIDC, autoRefresh: Bool = false) {
        self.configuration = oidc.configuration
        self.oidc = oidc
        self.autoRefresh = autoRefresh
    }

    @inlinable
    public func authenticate(request: Request, context: Context) async throws -> OIDCIdentity? {
        guard let session = context.sessions.session else { return nil }

        // Re-check access token expiry.
        if let expiresAt = session.accessTokenExpiresAt, expiresAt < Date() {
            if autoRefresh, let refreshToken = session.refreshToken {
                return try await attemptRefresh(session: session, refreshToken: refreshToken, context: context)
            }
            context.logger.debug("OIDC session access token expired")
            return nil
        }

        return OIDCIdentity(from: session)
    }

    @usableFromInline
    func attemptRefresh(
        session: OIDCSessionData,
        refreshToken: String,
        context: Context
    ) async throws -> OIDCIdentity? {
        let previousIdentity = OIDCIdentity(from: session)
        do {
            let refreshed = try await oidc.refreshIdentity(
                refreshToken: refreshToken,
                previousIdentity: previousIdentity
            )
            context.sessions.setSession(OIDCSessionData(from: refreshed))
            return refreshed
        } catch {
            context.logger.debug(
                "OIDC auto-refresh failed, forcing re-login",
                metadata: ["error": "\(error)"]
            )
            return nil
        }
    }
}
