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

import Hummingbird
import HummingbirdAuth

/// Basic password authenticator
///
/// Extract username and password from "Authorization" header and checks user exists and that the password is correct
public struct BasicAuthenticator<
    Context: AuthRequestContext,
    Repository: UserPasswordRepository,
    Verifier: PasswordHashVerifier
>: AuthenticatorMiddleware where Context.Identity == Repository.User {
    public typealias Identity = Context.Identity

    public let users: Repository
    public let passwordHashVerifier: Verifier

    /// Initialize BasicAuthenticator middleware
    /// - Parameters:
    ///   - users: User repository
    ///   - passwordHashVerifier: password verifier
    ///   - context: Request context type
    public init(users: Repository, passwordHashVerifier: Verifier = BcryptPasswordVerifier(), context: Context.Type = Context.self) {
        self.users = users
        self.passwordHashVerifier = passwordHashVerifier
    }

    /// Initialize BasicAuthenticator middleware
    /// - Parameters:
    ///   - passwordHashVerifier: password verifier
    ///   - context: Request context type
    ///   - getUser: Closure returning user type
    public init(
        passwordHashVerifier: Verifier = BcryptPasswordVerifier(),
        context: Context.Type = Context.self,
        getUser: @escaping @Sendable (String, UserRepositoryContext) async throws -> Context.Identity?
    ) where Identity: PasswordAuthenticatable, Repository == UserPasswordClosureRepository<Identity> {
        self.users = .init(getUser)
        self.passwordHashVerifier = passwordHashVerifier
    }

    @inlinable
    public func authenticate(request: Request, context: Context) async throws -> Repository.User? {
        // does request have basic authentication info in the "Authorization" header
        guard let basic = request.headers.basic else { return nil }

        // check if user exists and then verify the entered password against the one stored in the database.
        // If it is correct then login in user
        let user = try await users.getUser(named: basic.username, context: .init(logger: context.logger))
        guard let user, let passwordHash = user.passwordHash else { return nil }
        // Verify password hash on a separate thread to not block the general task executor
        guard try await self.passwordHashVerifier.verifyPassword(basic.password, createsHash: passwordHash) else { return nil }
        return user
    }
}
