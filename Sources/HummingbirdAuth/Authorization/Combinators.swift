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
/// .add(middleware: AuthorizationPolicyMiddleware(Not(RolePolicy("banned"))))
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

// MARK: - Optional wrappers
//
// Two separate types because the identity element differs per algebra:
//   allOf  — absent branch is vacuously true  (AND with no constraint)
//   anyOf  — absent branch is vacuously false (OR with no contribution)

/// Produced by `AllOfBuilder.buildOptional`. An absent `if` branch passes.
@_documentation(visibility: internal)
public struct _AllOfOptionalPolicy<Policy: AuthorizationPolicy>: AuthorizationPolicy {
    public typealias Identity = Policy.Identity
    @usableFromInline let policy: Policy?
    @usableFromInline init(_ policy: Policy?) { self.policy = policy }
    @inlinable
    public func isAuthorized(identity: Policy.Identity, request: Request) async throws -> Bool {
        try await policy?.isAuthorized(identity: identity, request: request) ?? true
    }
}

/// Produced by `AnyOfBuilder.buildOptional`. An absent `if` branch fails.
@_documentation(visibility: internal)
public struct _AnyOfOptionalPolicy<Policy: AuthorizationPolicy>: AuthorizationPolicy {
    public typealias Identity = Policy.Identity
    @usableFromInline let policy: Policy?
    @usableFromInline init(_ policy: Policy?) { self.policy = policy }
    @inlinable
    public func isAuthorized(identity: Policy.Identity, request: Request) async throws -> Bool {
        try await policy?.isAuthorized(identity: identity, request: request) ?? false
    }
}

// MARK: - Result builders

@resultBuilder
public enum AllOfBuilder<Identity: Sendable> {
    public static func buildExpression<Policy: AuthorizationPolicy>(_ policy: Policy) -> Policy
    where Policy.Identity == Identity { policy }
    public static func buildPartialBlock<Policy: AuthorizationPolicy>(first: Policy) -> Policy { first }
    public static func buildPartialBlock<Accumulated: AuthorizationPolicy, Next: AuthorizationPolicy>(
        accumulated: Accumulated,
        next: Next
    ) -> _AllOfPair<Accumulated, Next>
    where Accumulated.Identity == Next.Identity { _AllOfPair(accumulated, next) }
    public static func buildOptional<Policy: AuthorizationPolicy>(
        _ policy: Policy?
    ) -> _AllOfOptionalPolicy<Policy> { _AllOfOptionalPolicy(policy) }
    public static func buildEither<Policy: AuthorizationPolicy>(first: Policy) -> Policy { first }
    public static func buildEither<Policy: AuthorizationPolicy>(second: Policy) -> Policy { second }
}

@resultBuilder
public enum AnyOfBuilder<Identity: Sendable> {
    public static func buildExpression<Policy: AuthorizationPolicy>(_ policy: Policy) -> Policy
    where Policy.Identity == Identity { policy }
    public static func buildPartialBlock<Policy: AuthorizationPolicy>(first: Policy) -> Policy { first }
    public static func buildPartialBlock<Accumulated: AuthorizationPolicy, Next: AuthorizationPolicy>(
        accumulated: Accumulated,
        next: Next
    ) -> _AnyOfPair<Accumulated, Next>
    where Accumulated.Identity == Next.Identity { _AnyOfPair(accumulated, next) }
    public static func buildOptional<Policy: AuthorizationPolicy>(
        _ policy: Policy?
    ) -> _AnyOfOptionalPolicy<Policy> { _AnyOfOptionalPolicy(policy) }
    public static func buildEither<Policy: AuthorizationPolicy>(first: Policy) -> Policy { first }
    public static func buildEither<Policy: AuthorizationPolicy>(second: Policy) -> Policy { second }
}

// MARK: - Builder functions

/// Combines policies with AND semantics — all must pass.
///
/// Evaluation short-circuits on the first failing policy.
///
/// ```swift
/// .add(middleware: AuthorizationPolicyMiddleware(allOf {
///     RolePolicy("editor")
///     PermissionPolicy("posts:publish")
///     if requiresApproval { PermissionPolicy("posts:approved") }
/// }))
/// ```
public func allOf<Identity: Sendable>(
    @AllOfBuilder<Identity> _ build: () -> some AuthorizationPolicy<Identity>
) -> some AuthorizationPolicy<Identity> {
    build()
}

/// Combines policies with OR semantics — at least one must pass.
///
/// Evaluation short-circuits on the first passing policy.
///
/// ```swift
/// .add(middleware: AuthorizationPolicyMiddleware(anyOf {
///     RolePolicy("admin")
///     RolePolicy("moderator")
///     if legacyModeEnabled { RolePolicy("legacy-admin") }
/// }))
/// ```
public func anyOf<Identity: Sendable>(
    @AnyOfBuilder<Identity> _ build: () -> some AuthorizationPolicy<Identity>
) -> some AuthorizationPolicy<Identity> {
    build()
}
