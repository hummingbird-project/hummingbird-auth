//===----------------------------------------------------------------------===//
//
// This source file is part of the Hummingbird server framework project
//
// Copyright (c) 2021-2024 the Hummingbird authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See hummingbird/CONTRIBUTORS.txt for the list of Hummingbird authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Hummingbird

/// Repository of users identified by an id
public protocol UserRepository<Identifier, User, Context>: Sendable {
    associatedtype Identifier: Codable
    associatedtype Context: AuthRequestContext
    associatedtype User: Authenticatable

    ///  Get user from repository
    /// - Parameters:
    ///   - id: User ID
    ///   - context: Request context
    /// - Returns: User if there is one associated with supplied id
    func getUser(from id: Identifier, context: Context) async throws -> User?
}

/// Implementation of UserRepository that uses a closure
public struct UserClosureRepository<Identifier: Codable, User: Authenticatable, Context: AuthRequestContext>: UserRepository {
    @usableFromInline
    let getUserClosure: @Sendable (Identifier, Context) async throws -> User?

    public init(_ getUserClosure: @escaping @Sendable (Identifier, Context) async throws -> User?) {
        self.getUserClosure = getUserClosure
    }

    @inlinable
    public func getUser(from id: Identifier, context: Context) async throws -> User? {
        try await self.getUserClosure(id, context)
    }
}
