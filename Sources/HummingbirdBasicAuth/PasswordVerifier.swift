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
