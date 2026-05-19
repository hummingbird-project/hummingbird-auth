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
/// Conform your identity type to `RoleProviding` to enable ``RolePolicy``:
///
/// ```swift
/// struct User: RoleProviding {
///     var roles: Set<String>
/// }
/// ```
///
/// The `Roles` associated type can be any `SetAlgebra` conformance — commonly
/// `Set<Role>`, but a compact array-backed type works equally well for identities
/// that hold only a handful of roles:
///
/// ```swift
/// enum Role: String, Hashable, Sendable { case admin, editor, moderator }
///
/// struct User: RoleProviding {
///     var roles: Set<Role>         // Set for general use
///     // or: var roles: MyArraySet<Role>  // linear scan, faster for N < ~8
/// }
/// ```
///
/// - Note: `RoleProviding` and ``PermissionProviding`` are structurally identical
///   protocols. They are kept separate so that a type may conform to one without
///   the other (roles without permissions, or vice-versa), and so that the type
///   system can enforce that ``RolePolicy`` only applies to role-aware identities
///   while ``PermissionPolicy`` only applies to permission-aware identities.
public protocol RoleProviding: Sendable {
    /// The collection type used to store roles.
    ///
    /// Must conform to `SetAlgebra` so that ``RolePolicy`` can call `contains`.
    /// The element type (`Roles.Element`) is the role type — commonly `String`
    /// or a dedicated `enum`.
    associatedtype Roles: SetAlgebra & Sendable where Roles.Element: Equatable & Sendable

    /// The collection of roles this identity holds.
    var roles: Roles { get }
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
    let role: Identity.Roles.Element

    /// Initialize with the role to require.
    public init(_ role: Identity.Roles.Element) {
        self.role = role
    }

    @inlinable
    public func isAuthorized(identity: Identity, request: Request) async throws -> Bool {
        identity.roles.contains(self.role)
    }
}
