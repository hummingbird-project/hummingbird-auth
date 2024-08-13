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
import Logging

public protocol SessionUserRepository: Sendable {
    associatedtype User: Authenticatable
    associatedtype Session: Codable

    func getUser(from session: Session, logger: Logger) async throws -> User?
}

/// Implementation of SessionUserRepository that uses a closure
public struct UserSessionClosure<Session: Codable, User: Authenticatable>: SessionUserRepository {
    @usableFromInline
    let getUserClosure: @Sendable (Session, Logger) async throws -> User?

    @inlinable
    public func getUser(from id: Session, logger: Logger) async throws -> User? {
        try await self.getUserClosure(id, logger)
    }
}

/// Session authenticator
public struct SessionAuthenticator<Context: RequestContext & AuthRequestContext, Repository: SessionUserRepository>: AuthenticatorMiddleware {
    /// User repository
    public let users: Repository

    /// container for session objects
    public let sessionStorage: SessionStorage

    /// Initialize SessionAuthenticator middleware
    /// - Parameters:
    ///   - users: User repository
    ///   - sessionStorage: session storage
    public init(users: Repository, sessionStorage: SessionStorage) {
        self.users = users
        self.sessionStorage = sessionStorage
    }

    /// Initialize SessionAuthenticator middleware
    /// - Parameters:
    ///   - sessionStorage: session storage
    ///   - getUser: Closure returning user type from session id
    public init<Session: Codable, User: Authenticatable>(
        sessionStorage: SessionStorage,
        getUser: @escaping @Sendable (Session, Logger) async throws -> User?
    ) where Repository == UserSessionClosure<Session, User> {
        self.users = UserSessionClosure(getUserClosure: getUser)
        self.sessionStorage = sessionStorage
    }

    @inlinable
    public func authenticate(request: Request, context: Context) async throws -> Repository.User? {
        guard let session: Repository.Session = try await self.sessionStorage.load(request: request) else { return nil }
        return try await self.users.getUser(from: session, logger: context.logger)
    }
}
