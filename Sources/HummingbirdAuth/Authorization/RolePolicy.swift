//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import Hummingbird

/// A type whose instances carry a collection of roles.
///
/// ```swift
/// struct User: RoleProviding {
///     var roles: Set<String>
/// }
///
/// // Typed enum (recommended — compile-time exhaustiveness)
/// enum Role: String, Hashable, Sendable { case admin, editor, moderator }
/// struct User: RoleProviding { var roles: Set<Role> }
/// ```
///
/// The `Roles` associated type can be any `SetAlgebra` conformance — `Set<Role>` is the
/// most common choice, but a compact array-backed type is equally valid for identities
/// that hold only a handful of roles.
public protocol RoleProviding: Sendable {
    /// A `SetAlgebra` collection whose `Element` is the role type.
    associatedtype Roles: SetAlgebra & Sendable where Roles.Element: Sendable

    /// The roles this identity holds.
    var roles: Roles { get }
}

/// Requires the identity to hold a specific role.
///
/// ```swift
/// .authorized { RolePolicy("admin") }
///
/// // OR
/// .authorized { anyOf(RolePolicy("admin"), RolePolicy("moderator")) }
///
/// // AND NOT
/// .authorized { allOf(RolePolicy("editor"), Not(RolePolicy("banned"))) }
/// ```
public struct RolePolicy<Identity: RoleProviding>: AuthorizationPolicy {
    @usableFromInline
    let role: Identity.Roles.Element

    public init(_ role: Identity.Roles.Element) {
        self.role = role
    }

    @inlinable
    public func isAuthorized(identity: Identity, request: Request) async throws -> Bool {
        identity.roles.contains(self.role)
    }
}
