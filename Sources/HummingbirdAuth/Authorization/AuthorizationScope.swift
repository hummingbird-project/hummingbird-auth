//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import Hummingbird

/// Determines which resources an authenticated identity may see.
///
/// Works in two phases with ``QueryFilter``:
///
/// 1. ``filter(for:request:)`` runs once — resolves allowed IDs, fetches policy
///    decisions, reads from cache — and returns a ``QueryFilter``.
/// 2. ``QueryFilter/matches(_:)`` runs per element using data already in memory.
///
/// ```swift
/// struct DocumentScope: AuthorizationScope {
///     typealias Identity = User
///     typealias Filter = ClosureQueryFilter<Document>
///
///     func filter(for identity: User, request: Request) async throws -> Filter {
///         // Async work here — called once regardless of collection size
///         let allowed = try await store.list(subject: identity.id, relation: .viewer)
///         return ClosureQueryFilter { document in
///             document.id.map { allowed.contains($0) } ?? false
///         }
///     }
/// }
/// ```
///
/// Apply with ``Sequence/filter(scope:identity:request:)`` in a collection handler:
///
/// ```swift
/// func list(_ request: Request, context: Context) async throws -> [DocumentResponse] {
///     let identity = try context.requireIdentity()
///     return try await Document.query(on: db).all()
///         .filter(scope: documentScope, identity: identity, request: request)
///         .map { DocumentResponse(from: $0) }
/// }
/// ```
public protocol AuthorizationScope<Identity>: Sendable {
    /// The identity type this scope evaluates.
    associatedtype Identity: Sendable

    /// The filter type produced by this scope.
    associatedtype Filter: QueryFilter

    /// Resolve the filter for this identity.
    /// Called once per collection request; the returned ``QueryFilter`` is
    /// applied to each element in the collection.
    func filter(for identity: Identity, request: Request) async throws -> Filter
}

// MARK: - Sequence integration

extension Sequence {
    /// Returns elements the given identity may see according to `scope`.
    ///
    /// ```swift
    /// return try await Document.query(on: db).all()
    ///     .filter(scope: documentScope, identity: identity, request: request)
    ///     .map { DocumentResponse(from: $0) }
    /// ```
    public func filter<Scope: AuthorizationScope>(
        scope: Scope,
        identity: Scope.Identity,
        request: Request
    ) async throws -> [Element] where Scope.Filter.Resource == Element {
        let queryFilter = try await scope.filter(for: identity, request: request)
        var result: [Element] = []
        result.reserveCapacity(underestimatedCount)
        for element in self {
            if try await queryFilter.matches(element) {
                result.append(element)
            }
        }
        return result
    }
}
