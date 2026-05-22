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
/// ```swift
/// struct User: PermissionProviding {
///     var permissions: Set<String>
/// }
///
/// // Typed enum (recommended)
/// enum Permission: String, Hashable, Sendable {
///     case postsRead = "posts:read"
///     case postsWrite = "posts:write"
/// }
/// struct User: PermissionProviding { var permissions: Set<Permission> }
/// ```
///
/// A type can conform to both ``RoleProviding`` and `PermissionProviding`,
/// enabling ``RolePolicy`` and ``PermissionPolicy`` to be mixed freely.
public protocol PermissionProviding: Sendable {
    /// A `SetAlgebra` collection whose `Element` is the permission type.
    associatedtype Permissions: SetAlgebra & Sendable where Permissions.Element: Sendable

    /// The permissions this identity holds.
    var permissions: Permissions { get }
}

/// Requires the identity to hold a specific permission.
///
/// ```swift
/// .add(middleware: AuthorizationPolicyMiddleware(PermissionPolicy("posts:publish")))
///
/// // Role OR permission
/// .add(middleware: AuthorizationPolicyMiddleware(anyOf { RolePolicy("admin"); PermissionPolicy("posts:delete") }))
///
/// // Role AND permission
/// .add(middleware: AuthorizationPolicyMiddleware(allOf { RolePolicy("editor"); PermissionPolicy("posts:publish") }))
/// ```
public struct PermissionPolicy<Identity: PermissionProviding>: AuthorizationPolicy {
    @usableFromInline
    let permission: Identity.Permissions.Element

    public init(_ permission: Identity.Permissions.Element) {
        self.permission = permission
    }

    @inlinable
    public func isAuthorized(identity: Identity, request: Request) async throws -> Bool {
        identity.permissions.contains(self.permission)
    }
}
