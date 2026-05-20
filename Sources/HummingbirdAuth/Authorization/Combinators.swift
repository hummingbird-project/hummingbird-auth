//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import Hummingbird

// MARK: - Internal binary nodes

@_documentation(visibility: internal)
public struct _AllOfPair<A: AuthorizationPolicy, B: AuthorizationPolicy>: AuthorizationPolicy
where A.Identity == B.Identity {
    public typealias Identity = A.Identity
    @usableFromInline let first: A
    @usableFromInline let second: B
    @usableFromInline init(_ first: A, _ second: B) {
        self.first = first
        self.second = second
    }
    @inlinable
    public func isAuthorized(identity: A.Identity, request: Request) async throws -> Bool {
        guard try await first.isAuthorized(identity: identity, request: request) else { return false }
        return try await second.isAuthorized(identity: identity, request: request)
    }
}

@_documentation(visibility: internal)
public struct _AnyOfPair<A: AuthorizationPolicy, B: AuthorizationPolicy>: AuthorizationPolicy
where A.Identity == B.Identity {
    public typealias Identity = A.Identity
    @usableFromInline let first: A
    @usableFromInline let second: B
    @usableFromInline init(_ first: A, _ second: B) {
        self.first = first
        self.second = second
    }
    @inlinable
    public func isAuthorized(identity: A.Identity, request: Request) async throws -> Bool {
        if try await first.isAuthorized(identity: identity, request: request) { return true }
        return try await second.isAuthorized(identity: identity, request: request)
    }
}

// MARK: - Not

/// Inverts the result of another policy.
///
/// ```swift
/// .authorized {
///     Not(RolePolicy("banned"))
/// }
/// ```
public struct Not<Policy: AuthorizationPolicy>: AuthorizationPolicy {
    public typealias Identity = Policy.Identity
    @usableFromInline let policy: Policy
    public init(_ policy: Policy) { self.policy = policy }
    @inlinable
    public func isAuthorized(identity: Policy.Identity, request: Request) async throws -> Bool {
        try await !self.policy.isAuthorized(identity: identity, request: request)
    }
}

// MARK: - Result builders

@resultBuilder
public enum AllOfBuilder<Identity: Sendable> {
    public static func buildExpression<P: AuthorizationPolicy>(_ policy: P) -> P
    where P.Identity == Identity { policy }
    public static func buildPartialBlock<P: AuthorizationPolicy>(first: P) -> P { first }
    public static func buildPartialBlock<Acc: AuthorizationPolicy, Next: AuthorizationPolicy>(
        accumulated: Acc,
        next: Next
    ) -> _AllOfPair<Acc, Next> where Acc.Identity == Next.Identity { _AllOfPair(accumulated, next) }
    public static func buildOptional<P: AuthorizationPolicy>(_ policy: P?) -> _OptionalPolicy<P> {
        _OptionalPolicy(policy)
    }
    public static func buildEither<P: AuthorizationPolicy>(first: P) -> P { first }
    public static func buildEither<P: AuthorizationPolicy>(second: P) -> P { second }
}

@resultBuilder
public enum AnyOfBuilder<Identity: Sendable> {
    public static func buildExpression<P: AuthorizationPolicy>(_ policy: P) -> P
    where P.Identity == Identity { policy }
    public static func buildPartialBlock<P: AuthorizationPolicy>(first: P) -> P { first }
    public static func buildPartialBlock<Acc: AuthorizationPolicy, Next: AuthorizationPolicy>(
        accumulated: Acc,
        next: Next
    ) -> _AnyOfPair<Acc, Next> where Acc.Identity == Next.Identity { _AnyOfPair(accumulated, next) }
    public static func buildOptional<P: AuthorizationPolicy>(_ policy: P?) -> _OptionalPolicy<P> {
        _OptionalPolicy(policy)
    }
    public static func buildEither<P: AuthorizationPolicy>(first: P) -> P { first }
    public static func buildEither<P: AuthorizationPolicy>(second: P) -> P { second }
}

// MARK: - Optional wrapper

@_documentation(visibility: internal)
public struct _OptionalPolicy<Policy: AuthorizationPolicy>: AuthorizationPolicy {
    public typealias Identity = Policy.Identity
    @usableFromInline let policy: Policy?
    @usableFromInline init(_ policy: Policy?) { self.policy = policy }
    @inlinable
    public func isAuthorized(identity: Policy.Identity, request: Request) async throws -> Bool {
        try await policy?.isAuthorized(identity: identity, request: request) ?? true
    }
}

// MARK: - Two-argument combinators

/// Combines two policies with AND semantics — both must pass.
///
/// ```swift
/// .authorized {
///     allOf(RolePolicy("editor"), PermissionPolicy("posts:publish"))
/// }
/// ```
public func allOf<A: AuthorizationPolicy, B: AuthorizationPolicy>(
    _ first: A,
    _ second: B
) -> _AllOfPair<A, B> where A.Identity == B.Identity {
    _AllOfPair(first, second)
}

/// Combines two policies with OR semantics — at least one must pass.
///
/// ```swift
/// .authorized {
///     anyOf(RolePolicy("admin"), PermissionPolicy("posts:delete"))
/// }
/// ```
public func anyOf<A: AuthorizationPolicy, B: AuthorizationPolicy>(
    _ first: A,
    _ second: B
) -> _AnyOfPair<A, B> where A.Identity == B.Identity {
    _AnyOfPair(first, second)
}

// MARK: - Builder combinators

/// Combines any number of policies with AND semantics — all must pass.
///
/// Evaluation short-circuits on the first failing policy.
///
/// ```swift
/// .authorized {
///     allOf {
///         RolePolicy("editor")
///         PermissionPolicy("posts:publish")
///         if requiresApproval { PermissionPolicy("posts:approved") }
///     }
/// }
/// ```
public func allOf<Policy: AuthorizationPolicy>(
    @AllOfBuilder<Policy.Identity> _ build: () -> Policy
) -> Policy {
    build()
}

/// Combines any number of policies with OR semantics — at least one must pass.
///
/// Evaluation short-circuits on the first passing policy.
///
/// ```swift
/// .authorized {
///     anyOf {
///         RolePolicy("admin")
///         RolePolicy("moderator")
///         if legacyModeEnabled { RolePolicy("legacy-admin") }
///     }
/// }
/// ```
public func anyOf<Policy: AuthorizationPolicy>(
    @AnyOfBuilder<Policy.Identity> _ build: () -> Policy
) -> Policy {
    build()
}
