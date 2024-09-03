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
import HummingbirdAuth
import Logging

/// Repository of users identified by an id
public protocol UserPasswordRepository<User>: Sendable {
    associatedtype User: PasswordAuthenticatable

    ///  Get user from repository
    /// - Parameters:
    ///   - id: User ID
    ///   - context: Request context
    /// - Returns: User if there is one associated with supplied id
    func getUser(named username: String, context: UserRepositoryContext) async throws -> User?
}

/// Implementation of UserRepository that uses a closure
public struct UserPasswordClosureRepository<User: PasswordAuthenticatable>: UserPasswordRepository {
    @usableFromInline
    let getUserClosure: @Sendable (String, UserRepositoryContext) async throws -> User?

    public init(_ getUserClosure: @escaping @Sendable (String, UserRepositoryContext) async throws -> User?) {
        self.getUserClosure = getUserClosure
    }

    @inlinable
    public func getUser(named username: String, context: UserRepositoryContext) async throws -> User? {
        try await self.getUserClosure(username, context)
    }
}
