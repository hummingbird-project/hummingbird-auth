//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import Hummingbird

/// Protocol for authorization policies.
///
/// An `AuthorizationPolicy` determines whether an authenticated identity is allowed
/// to proceed with a given request. Policies are evaluated *after* authentication —
/// the identity is already resolved in the request context.
///
/// Implement this protocol to create reusable, composable authorization rules.
/// For one-off rules, use ``ClosureAuthorizationPolicy``.
///
/// Policies can be composed using ``AllOf``, ``AnyOf``, and ``Not`` combinators:
///
/// ```swift
/// IsAuthorizedMiddleware(
///     AnyOf(
///         RolePolicy("admin"),
///         AllOf(RolePolicy("editor"), PermissionPolicy("posts:publish"))
///     )
/// )
/// ```
public protocol AuthorizationPolicy<Identity>: Sendable {
    /// The identity type this policy evaluates.
    associatedtype Identity: Sendable

    /// Evaluate whether the given identity is authorized to proceed with the request.
    ///
    /// - Parameters:
    ///   - identity: The authenticated identity resolved by the preceding authenticator.
    ///   - request: The incoming HTTP request.
    /// - Returns: `true` if the identity is authorized, `false` to produce a 403 response.
    /// - Throws: Any error, which propagates up the middleware chain unchanged.
    func isAuthorized(identity: Identity, request: Request) async throws -> Bool
}

/// An ``AuthorizationPolicy`` backed by a closure.
///
/// Use this as an escape hatch when a full policy type is unnecessary:
///
/// ```swift
/// IsAuthorizedMiddleware(
///     ClosureAuthorizationPolicy { user, request in
///         user.id == request.uri.queryParameters.get("userId")
///     }
/// )
/// ```
public struct ClosureAuthorizationPolicy<Identity: Sendable>: AuthorizationPolicy {
    @usableFromInline
    let closure: @Sendable (Identity, Request) async throws -> Bool

    /// Initialize with a closure.
    /// - Parameter closure: Receives the authenticated identity and the incoming request.
    ///   Return `true` to allow, `false` to deny.
    public init(_ closure: @escaping @Sendable (Identity, Request) async throws -> Bool) {
        self.closure = closure
    }

    @inlinable
    public func isAuthorized(identity: Identity, request: Request) async throws -> Bool {
        try await self.closure(identity, request)
    }
}
