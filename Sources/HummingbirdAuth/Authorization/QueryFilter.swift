//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import Hummingbird

/// The evaluation half of the two-phase collection authorization pattern.
///
/// ``AuthorizationScope/filter(for:request:)`` is the *resolution* phase — it runs
/// once per request and does the async work (store queries, policy engine calls).
/// `QueryFilter` is the *evaluation* phase — ``matches(_:)`` is called once per
/// resource using data already in memory, with no further I/O.
///
/// ```
/// AuthorizationScope.filter(for:request:)  →  async, once    (resolve allowed IDs)
/// QueryFilter.matches(_:)                  →  sync,  N times  (check each resource)
/// ```
public protocol QueryFilter<Resource>: Sendable {
    /// The resource type this filter operates on.
    associatedtype Resource: Sendable

    /// Return `true` if this resource should be included in the result.
    func matches(_ resource: Resource) async throws -> Bool
}

/// A ``QueryFilter`` backed by a closure.
public struct ClosureQueryFilter<Resource: Sendable>: QueryFilter {
    @usableFromInline
    let closure: @Sendable (Resource) async throws -> Bool

    /// - Parameter closure: Return `true` to include the resource, `false` to exclude it.
    public init(_ closure: @escaping @Sendable (Resource) async throws -> Bool) {
        self.closure = closure
    }

    @inlinable
    public func matches(_ resource: Resource) async throws -> Bool {
        try await closure(resource)
    }
}
