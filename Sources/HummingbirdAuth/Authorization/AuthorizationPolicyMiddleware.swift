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
///     .add(middleware: AuthorizationPolicyMiddleware(RolePolicy("admin")))
///     .get("admin/dashboard") { _, _ in ... }
/// ```
///
/// Policies compose freely via `allOf { }`, `anyOf { }`, and ``Not``:
///
/// ```swift
/// AuthorizationPolicyMiddleware(anyOf {
///     RolePolicy("admin")
///     allOf { RolePolicy("editor"); PermissionPolicy("posts:publish") }
/// })
/// ```
///
/// ### Customising the denial error
///
/// By default a denied request throws `403 Forbidden`. Supply any
/// `HTTPResponseError`-conforming value as `deniedError` to override this —
/// a common need is returning `404 Not Found` to avoid leaking whether a resource
/// exists to callers who are not permitted to see it:
///
/// ```swift
/// AuthorizationPolicyMiddleware(
///     RolePolicy("admin"),
///     deniedError: HTTPError(.notFound)
/// )
/// ```
///
/// Supply your own error type for full control over the response body and headers:
///
/// ```swift
/// struct AuthorizationError: HTTPResponseError {
///     var status: HTTPResponse.Status { .forbidden }
///     func response(from request: Request, context: some RequestContext) -> Response {
///         Response(status: .forbidden, headers: ["X-Reason": "insufficient-role"])
///     }
/// }
///
/// AuthorizationPolicyMiddleware(RolePolicy("admin"), deniedError: AuthorizationError())
/// ```
///
/// - Throws `HTTPError(.unauthorized)` (401) if the request context carries no identity.
/// - Throws `deniedError` (default: `HTTPError(.forbidden)` 403) if the policy denies.
public struct AuthorizationPolicyMiddleware<
    Policy: AuthorizationPolicy,
    Context: AuthRequestContext,
    DeniedError: HTTPResponseError
>: RouterMiddleware where Context.Identity == Policy.Identity {

    @usableFromInline
    let policy: Policy
    @usableFromInline
    let deniedError: DeniedError

    /// Initialize with an authorization policy.
    /// - Parameters:
    ///   - policy: The policy evaluated for every request in this middleware group.
    ///   - deniedError: The `HTTPResponseError` thrown when the policy denies the request.
    ///     Defaults to `HTTPError(.forbidden)` (403).
    ///   - context: The request context type (used for type inference only).
    public init(
        _ policy: Policy,
        deniedError: DeniedError = HTTPError(.forbidden),
        context: Context.Type = Context.self
    ) {
        self.policy = policy
        self.deniedError = deniedError
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
            throw self.deniedError
        }
        return try await next(request, context)
    }
}
