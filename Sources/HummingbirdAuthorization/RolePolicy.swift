//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import Hummingbird

/// A type whose instances carry a set of roles.
///
/// Conform your identity type to `RoleProviding` to enable ``RolePolicy``:
///
/// ```swift
/// struct User: RoleProviding {
///     var roles: Set<String>
/// }
/// ```
///
/// The `Role` associated type can be any `Hashable & Sendable` value — commonly
/// a `String` or a custom enum for compile-time exhaustiveness:
///
/// ```swift
/// enum Role: String, Hashable, Sendable {
///     case admin, editor, moderator, user, banned
/// }
///
/// struct User: RoleProviding {
///     var roles: Set<Role>
/// }
/// ```
public protocol RoleProviding: Sendable {
    /// The role type. Commonly `String` or a dedicated `enum`.
    associatedtype Role: Hashable & Sendable

    /// The set of roles this identity holds.
    var roles: Set<Role> { get }
}

/// A policy that requires the identity to hold a specific role.
///
/// Combine with ``AnyOf``, ``AllOf``, and ``Not`` for richer rules:
///
/// ```swift
/// // Pass if the user is an admin
/// RolePolicy("admin")
///
/// // Pass if the user is an admin OR a moderator
/// AnyOf(RolePolicy("admin"), RolePolicy("moderator"))
///
/// // Pass if the user is both verified AND an editor
/// AllOf(RolePolicy("editor"), RolePolicy("verified"))
///
/// // Pass if the user is NOT banned
/// Not(RolePolicy("banned"))
/// ```
public struct RolePolicy<Identity: RoleProviding>: AuthorizationPolicy {
    @usableFromInline
    let role: Identity.Role

    /// Initialize with the role to require.
    public init(_ role: Identity.Role) {
        self.role = role
    }

    @inlinable
    public func isAuthorized(identity: Identity, request: Request) async throws -> Bool {
        identity.roles.contains(self.role)
    }
}
