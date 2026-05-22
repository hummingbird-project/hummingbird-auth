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
/// The `Roles` associated type can be any `SetAlgebra` conformance.
/// `Set<Role>` is the most common choice, but `OptionSet` works equally well and is
/// more efficient when roles map naturally to a bitmask:
///
/// ```swift
/// struct Roles: OptionSet, Sendable {
///     let rawValue: UInt8
///     static let admin     = Roles(rawValue: 1 << 0)
///     static let editor    = Roles(rawValue: 1 << 1)
///     static let moderator = Roles(rawValue: 1 << 2)
/// }
///
/// struct User: RoleProviding {
///     var roles: Roles   // single byte; bitwise contains check
/// }
/// ```
///
/// With an `OptionSet`, `RolePolicy(.admin)` checks whether the admin bit is set
/// in a single bitwise operation.
public protocol RoleProviding: Sendable {
    /// A `SetAlgebra` collection whose `Element` is the role type.
    associatedtype Roles: SetAlgebra & Sendable where Roles.Element: Sendable

    /// The roles this identity holds.
    var roles: Roles { get }
}

/// Requires the identity to hold a specific role.
///
/// ```swift
/// .add(middleware: AuthorizationPolicyMiddleware(RolePolicy("admin")))
///
/// // OR
/// .add(middleware: AuthorizationPolicyMiddleware(anyOf { RolePolicy("admin"); RolePolicy("moderator") }))
///
/// // AND NOT
/// .add(middleware: AuthorizationPolicyMiddleware(allOf { RolePolicy("editor"); Not(RolePolicy("banned")) }))
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
