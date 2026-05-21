//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import Hummingbird

/// A resolved filter returned by ``AuthorizationScope/filter(for:request:)``.
///
/// The concrete type carries whatever data was resolved during the async
/// computation — a set of allowed IDs, a predicate, a list of constraints —
/// and applies it synchronously per resource via ``matches(_:)``.
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
