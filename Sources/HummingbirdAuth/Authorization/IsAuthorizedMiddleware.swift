//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import Hummingbird

/// Middleware that enforces an ``AuthorizationPolicy`` on every request it handles.
///
/// Place this middleware *after* an authenticator and ``IsAuthenticatedMiddleware``
/// in the middleware chain:
///
/// ```swift
/// router.group()
///     .add(middleware: MyAuthenticator())
///     .add(middleware: IsAuthenticatedMiddleware())
///     .add(middleware: IsAuthorizedMiddleware(RolePolicy("admin")))
///     .get("admin/dashboard") { _, _ in ... }
/// ```
///
/// Policies compose freely via ``AllOf``, ``AnyOf``, and ``Not``:
///
/// ```swift
/// IsAuthorizedMiddleware(
///     AnyOf(
///         RolePolicy("admin"),
///         AllOf(RolePolicy("editor"), PermissionPolicy("posts:publish"))
///     )
/// )
/// ```
///
/// ### Customising the denial error
///
/// By default a denied request throws `403 Forbidden`. Pass `unauthorizedError`
/// to override this — a common need is returning `404 Not Found` to avoid
/// leaking the existence of a resource the caller cannot see:
///
/// ```swift
/// IsAuthorizedMiddleware(
///     RolePolicy("admin"),
///     unauthorizedError: HTTPError(.notFound)
/// )
/// ```
///
/// - Throws ``HTTPError(.unauthorized)`` (401) if the request context carries no identity.
/// - Throws `unauthorizedError` (default: ``HTTPError(.forbidden)`` 403) if the policy denies.
public struct IsAuthorizedMiddleware<
    Policy: AuthorizationPolicy,
    Context: AuthRequestContext
>: RouterMiddleware where Context.Identity == Policy.Identity {

    @usableFromInline
    let policy: Policy
    @usableFromInline
    let unauthorizedError: HTTPError

    /// Initialize with an authorization policy.
    /// - Parameters:
    ///   - policy: The policy evaluated for every request in this middleware group.
    ///   - unauthorizedError: The error thrown when the policy denies the request.
    ///     Defaults to `HTTPError(.forbidden)` (403).
    ///   - context: The request context type (used for type inference only).
    public init(
        _ policy: Policy,
        unauthorizedError: HTTPError = HTTPError(.forbidden),
        context: Context.Type = Context.self
    ) {
        self.policy = policy
        self.unauthorizedError = unauthorizedError
    }

    @inlinable
    public func handle(
        _ request: Request,
        context: Context,
        next: (Request, Context) async throws -> Response
    ) async throws -> Response {
        guard let identity = context.identity else {
            throw HTTPError(.unauthorized)
        }
        guard try await self.policy.isAuthorized(identity: identity, request: request) else {
            throw self.unauthorizedError
        }
        return try await next(request, context)
    }
}
