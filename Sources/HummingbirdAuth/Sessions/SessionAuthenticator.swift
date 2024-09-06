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

/// Session authenticator
public struct SessionAuthenticator<Context: AuthRequestContext, Repository: UserSessionRepository>: AuthenticatorMiddleware {
    /// User repository
    public let users: Repository

    /// container for session objects
    public let sessionStorage: SessionStorage

    /// Initialize SessionAuthenticator middleware
    /// - Parameters:
    ///   - users: User repository
    ///   - sessionStorage: session storage
    public init(users: Repository, sessionStorage: SessionStorage, context: Context.Type = Context.self) {
        self.users = users
        self.sessionStorage = sessionStorage
    }

    /// Initialize SessionAuthenticator middleware
    /// - Parameters:
    ///   - sessionStorage: session storage
    ///   - getUser: Closure returning user type from session id
    public init<Session: Codable, User: Authenticatable>(
        sessionStorage: SessionStorage,
        context: Context.Type = Context.self,
        getUser: @escaping @Sendable (Session, UserRepositoryContext) async throws -> User?
    ) where Repository == UserSessionClosureRepository<Session, User> {
        self.users = UserSessionClosureRepository(getUser)
        self.sessionStorage = sessionStorage
    }

    @inlinable
    public func authenticate(request: Request, context: Context) async throws -> Repository.User? {
        guard let id: Repository.Identifier = try await self.sessionStorage.load(request: request) else { return nil }
        return try await self.users.getUser(from: id, context: .init(logger: context.logger))
    }
}
