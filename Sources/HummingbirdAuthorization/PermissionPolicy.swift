//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import Hummingbird

/// A type whose instances carry a set of fine-grained permissions.
///
/// Conform your identity type to `PermissionProviding` to enable ``PermissionPolicy``:
///
/// ```swift
/// struct User: PermissionProviding {
///     var permissions: Set<String>
/// }
/// ```
///
/// The `Permission` associated type can be any `Hashable & Sendable` value — commonly
/// a scoped `String` (e.g. `"posts:write"`) or a custom enum:
///
/// ```swift
/// enum Permission: String, Hashable, Sendable {
///     case postsRead   = "posts:read"
///     case postsWrite  = "posts:write"
///     case usersDelete = "users:delete"
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
public protocol PermissionProviding: Sendable {
    /// The permission type. Commonly `String` or a dedicated `enum`.
    associatedtype Permission: Hashable & Sendable

    /// The set of permissions this identity holds.
    var permissions: Set<Permission> { get }
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
    let permission: Identity.Permission

    /// Initialize with the permission to require.
    public init(_ permission: Identity.Permission) {
        self.permission = permission
    }

    @inlinable
    public func isAuthorized(identity: Identity, request: Request) async throws -> Bool {
        identity.permissions.contains(self.permission)
    }
}
