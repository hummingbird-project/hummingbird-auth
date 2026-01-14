//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import HummingbirdBcrypt
import NIOPosix

/// Protocol for password verifier
public protocol PasswordHashVerifier: Sendable {
    func verifyPassword(_ password: String, createsHash hash: String) async throws -> Bool
}

/// Bcrypt password verifier
public struct BcryptPasswordVerifier: PasswordHashVerifier {
    public init() {}

    @inlinable
    public func verifyPassword(_ password: String, createsHash hash: String) async throws -> Bool {
        try await NIOThreadPool.singleton.runIfActive {
            Bcrypt.verify(password, hash: hash)
        }
    }
}
