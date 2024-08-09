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

import Bcrypt
import NIOPosix

/// Bcrypt password verifier
public struct BcryptPasswordVerifier: PasswordVerifier {
    public func verifyPassword(_ text: String, hash: String) async throws -> Bool {
        try await NIOThreadPool.singleton.runIfActive {
            Bcrypt.verify(text, hash: hash)
        }
    }
}

extension BasicAuthenticator where Verifier == BcryptPasswordVerifier {
    /// Initialize BasicAuthenticator middleware using Bcrypt to verify passwords
    /// - Parameters:
    ///   - users: User repository
    public init(users: Repository) {
        self.users = users
        self.passwordVerifier = BcryptPasswordVerifier()
    }
}
