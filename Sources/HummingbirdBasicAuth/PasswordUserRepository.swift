//===----------------------------------------------------------------------===//
//
// This source file is part of the Hummingbird server framework project
//
// Copyright (c) 2024 the Hummingbird authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See hummingbird/CONTRIBUTORS.txt for the list of Hummingbird authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import HummingbirdAuth
import Logging

/// Protocol for user extracted from Storage
public protocol BasicAuthenticatorUser: Authenticatable {
    var username: String { get }
    var passwordHash: String? { get }
}

/// Protocol for user/password hash storage
public protocol PasswordUserRepository: Sendable {
    associatedtype User: BasicAuthenticatorUser

    func getUser(named name: String, logger: Logger) async throws -> User?
}

/// Implementation of UserPasswordRepository that uses a closure
public struct UserPasswordClosure<User>: PasswordUserRepository where User: BasicAuthenticatorUser {
    @usableFromInline
    let getUserClosure: @Sendable (String, Logger) async throws -> User?

    @inlinable
    public func getUser(named name: String, logger: Logger) async throws -> User? {
        try await self.getUserClosure(name, logger)
    }
}
