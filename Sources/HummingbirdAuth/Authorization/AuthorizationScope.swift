//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import Hummingbird

/// Answers *"given this identity, which resources can they see?"*
///
/// The complement to ``AuthorizationPolicy``, which answers the point query
/// *"can this identity see this specific resource?"*
///
/// All async work belongs in ``filter(for:request:)``. The returned
/// ``QueryFilter`` carries the resolved data and applies it per resource.
///
/// ```swift
/// struct DocumentScope: AuthorizationScope {
///     typealias Identity = User
///     typealias Filter = ClosureQueryFilter<Document>
///
///     func filter(for identity: User, request: Request) async throws -> Filter {
///         let ids = try await store.list(subject: identity.id)
///         let allowed = Set(ids)
///         return ClosureQueryFilter { document in
///             document.id.map { allowed.contains($0) } ?? false
///         }
///     }
/// }
/// ```
public protocol AuthorizationScope<Identity>: Sendable {
    /// The identity type this scope evaluates.
    associatedtype Identity: Sendable

    /// The filter type returned. Carries resolved constraint data and applies it
    /// to individual resources via ``QueryFilter/matches(_:)``.
    associatedtype Filter: QueryFilter

    /// Compute the filter for this identity. Called once per collection request.
    func filter(for identity: Identity, request: Request) async throws -> Filter
}
