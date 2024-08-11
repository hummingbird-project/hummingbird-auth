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

/// Protocol for user extracted from Storage
public protocol BasicAuthenticatorUser: Authenticatable {
    var username: String { get }
    var passwordHash: String? { get }
}

/// Protocol for user/password hash storage
public protocol UserPasswordRepository: Sendable {
    associatedtype User: BasicAuthenticatorUser

    func getUser(named name: String) async throws -> User?
}

/// Implementation of UserPasswordRepository that uses a closure
public struct UserPasswordClosure<User>: UserPasswordRepository where User: BasicAuthenticatorUser {
    let getUserClosure: @Sendable (String) async throws -> User?

    public func getUser(named name: String) async throws -> User? {
        try await self.getUserClosure(name)
    }
}
