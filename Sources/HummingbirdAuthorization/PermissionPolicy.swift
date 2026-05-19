//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import Hummingbird

/// A type whose instances carry a collection of fine-grained permissions.
///
/// Conform your identity type to `PermissionProviding` to enable ``PermissionPolicy``:
///
/// ```swift
/// struct User: PermissionProviding {
///     var permissions: Set<String>
/// }
/// ```
///
/// The `Permissions` associated type can be any `SetAlgebra` conformance — commonly
/// `Set<Permission>`, but a compact array-backed type works equally well for identities
/// that hold only a handful of permissions:
///
/// ```swift
/// enum Permission: String, Hashable, Sendable {
///     case postsRead = "posts:read", postsWrite = "posts:write"
/// }
///
/// struct User: PermissionProviding {
///     var permissions: Set<Permission>
/// }
/// ```
///
/// An identity type can conform to both ``RoleProviding`` and `PermissionProviding`,
/// allowing ``RolePolicy`` and ``PermissionPolicy`` to be freely mixed via
/// ``AllOf`` and ``AnyOf``.
///
/// - Note: `PermissionProviding` and ``RoleProviding`` are structurally identical
///   protocols. They are kept separate so that a type may conform to one without
///   the other (permissions without roles, or vice-versa), and so that the type
///   system can enforce that ``PermissionPolicy`` only applies to permission-aware
///   identities while ``RolePolicy`` only applies to role-aware identities.
public protocol PermissionProviding: Sendable {
    /// The collection type used to store permissions.
    ///
    /// Must conform to `SetAlgebra` so that ``PermissionPolicy`` can call `contains`.
    /// The element type (`Permissions.Element`) is the permission type — commonly
    /// a scoped `String` (e.g. `"posts:write"`) or a dedicated `enum`.
    associatedtype Permissions: SetAlgebra & Sendable where Permissions.Element: Sendable

    /// The collection of permissions this identity holds.
    var permissions: Permissions { get }
}

/// A policy that requires the identity to hold a specific permission.
///
/// Combine with ``AnyOf``, ``AllOf``, and ``Not`` for richer rules,
/// and mix freely with ``RolePolicy`` when the identity conforms to both
/// ``RoleProviding`` and ``PermissionProviding``:
///
/// ```swift
/// // Require a single permission
/// PermissionPolicy("posts:publish")
///
/// // Require any one of several permissions
/// AnyOf(PermissionPolicy("posts:write"), PermissionPolicy("posts:publish"))
///
/// // Combine role and permission checks on the same identity
/// AllOf(
///     RolePolicy("editor"),
///     PermissionPolicy("posts:publish")
/// )
/// ```
public struct PermissionPolicy<Identity: PermissionProviding>: AuthorizationPolicy {
    @usableFromInline
    let permission: Identity.Permissions.Element

    /// Initialize with the permission to require.
    public init(_ permission: Identity.Permissions.Element) {
        self.permission = permission
    }

    @inlinable
    public func isAuthorized(identity: Identity, request: Request) async throws -> Bool {
        identity.permissions.contains(self.permission)
    }
}
