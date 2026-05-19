//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import Hummingbird

/// A policy that passes only when **all** of its child policies pass.
///
/// Evaluation short-circuits on the first failing policy so subsequent policies
/// are not evaluated.
///
/// ```swift
/// // Require the user to be both an editor AND hold the publish permission
/// AllOf(
///     RolePolicy("editor"),
///     PermissionPolicy("posts:publish")
/// )
///
/// // Store as an opaque type when a let binding is needed
/// let policy: some AuthorizationPolicy<User> = AllOf(
///     RolePolicy<User>("editor"),
///     PermissionPolicy<User>("posts:publish")
/// )
/// ```
///
public struct AllOf<Identity: Sendable>: AuthorizationPolicy {
    @usableFromInline
    let policies: [any AuthorizationPolicy<Identity>]

    /// Initialize with a variadic list of policies.
    public init(_ policies: any AuthorizationPolicy<Identity>...) {
        self.policies = policies
    }

    /// Initialize with an array of policies.
    public init(_ policies: [any AuthorizationPolicy<Identity>]) {
        self.policies = policies
    }

    @inlinable
    public func isAuthorized(identity: Identity, request: Request) async throws -> Bool {
        for policy in self.policies {
            guard try await policy.isAuthorized(identity: identity, request: request) else {
                return false
            }
        }
        return true
    }
}

/// A policy that passes when **any** of its child policies pass.
///
/// Evaluation short-circuits on the first passing policy so subsequent policies
/// are not evaluated.
///
/// ```swift
/// // Allow admins or moderators through
/// AnyOf(
///     RolePolicy("admin"),
///     RolePolicy("moderator")
/// )
/// ```
///
public struct AnyOf<Identity: Sendable>: AuthorizationPolicy {
    @usableFromInline
    let policies: [any AuthorizationPolicy<Identity>]

    /// Initialize with a variadic list of policies.
    public init(_ policies: any AuthorizationPolicy<Identity>...) {
        self.policies = policies
    }

    /// Initialize with an array of policies.
    public init(_ policies: [any AuthorizationPolicy<Identity>]) {
        self.policies = policies
    }

    @inlinable
    public func isAuthorized(identity: Identity, request: Request) async throws -> Bool {
        for policy in self.policies {
            if try await policy.isAuthorized(identity: identity, request: request) {
                return true
            }
        }
        return false
    }
}

/// A policy that inverts the result of another policy.
///
/// ```swift
/// // Deny banned users
/// Not(RolePolicy("banned"))
///
/// // Compose freely with other combinators
/// AllOf(
///     RolePolicy("user"),
///     Not(RolePolicy("banned"))
/// )
/// ```
public struct Not<Policy: AuthorizationPolicy>: AuthorizationPolicy {
    public typealias Identity = Policy.Identity

    @usableFromInline
    let policy: Policy

    /// Initialize with the policy whose result will be inverted.
    public init(_ policy: Policy) {
        self.policy = policy
    }

    @inlinable
    public func isAuthorized(identity: Policy.Identity, request: Request) async throws -> Bool {
        try await !self.policy.isAuthorized(identity: identity, request: request)
    }
}
