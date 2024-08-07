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
import Hummingbird
import HummingbirdAuth
import NIOPosix

/// Protocol for user extracted from Storage
public protocol BasicUser: Authenticatable {
    var username: String { get }
    var passwordHash: String? { get }
}

/// Protocol for User storage
public protocol UserRepository: Sendable {
    associatedtype User: BasicUser

    func getUser(named name: String) async throws -> User?
}

/// Basic password authenticator
///
/// Extract username and password from "Authorization" header and checks user exists and that the password is correct
public struct BasicAuthenticator<Context: AuthRequestContext, Repository: UserRepository>: AuthenticatorMiddleware {
    let users: Repository

    public init(users: Repository) {
        self.users = users
    }

    public func authenticate(request: Request, context: Context) async throws -> Repository.User? {
        // does request have basic authentication info in the "Authorization" header
        guard let basic = request.headers.basic else { return nil }

        // check if user exists and then verify the entered password against the one stored in the database.
        // If it is correct then login in user
        let user = try await users.getUser(named: basic.username)
        guard let user, let passwordHash = user.passwordHash else { return nil }
        // Do Bcrypt verify on a separate thread to not block the general task executor
        guard try await NIOThreadPool.singleton.runIfActive({ Bcrypt.verify(basic.password, hash: passwordHash) }) else { return nil }
        return user
    }
}
