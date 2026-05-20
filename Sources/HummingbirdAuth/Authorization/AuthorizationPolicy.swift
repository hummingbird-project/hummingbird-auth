//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import Hummingbird

/// Determines whether an authenticated identity is permitted to proceed with a request.
///
/// Implement this protocol to create reusable, composable authorization rules.
/// For one-off rules use ``ClosureAuthorizationPolicy``.
///
/// Attach policies to a route group via ``RouterGroup/authorized(_:)``:
///
/// ```swift
/// router.group()
///     .add(middleware: MyAuthenticator())
///     .authorized {
///         RolePolicy("admin")
///     }
///     .get("dashboard") { _, _ in ... }
/// ```
public protocol AuthorizationPolicy<Identity>: Sendable {
    /// The identity type this policy evaluates.
    associatedtype Identity: Sendable

    /// Return `true` to allow the request, `false` to deny it with the configured
    /// `deniedError` (default `403 Forbidden`).
    func isAuthorized(identity: Identity, request: Request) async throws -> Bool
}

/// An ``AuthorizationPolicy`` backed by a closure.
///
/// ```swift
/// .authorized {
///     ClosureAuthorizationPolicy { user, request in
///         user.id == request.uri.queryParameters.get("userId")
///     }
/// }
/// ```
public struct ClosureAuthorizationPolicy<Identity: Sendable>: AuthorizationPolicy {
    @usableFromInline
    let closure: @Sendable (Identity, Request) async throws -> Bool

    /// - Parameter closure: Return `true` to allow, `false` to deny.
    public init(_ closure: @escaping @Sendable (Identity, Request) async throws -> Bool) {
        self.closure = closure
    }

    @inlinable
    public func isAuthorized(identity: Identity, request: Request) async throws -> Bool {
        try await self.closure(identity, request)
    }
}
