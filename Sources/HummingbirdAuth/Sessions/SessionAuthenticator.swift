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

public protocol SessionUserRepository: Sendable {
    associatedtype User: Authenticatable
    associatedtype UserID: Codable
    associatedtype Context: RequestContext & AuthRequestContext

    func getUser(from id: UserID, context: Context) async throws -> User?
}

/// Implementation of SessionUserRepository that uses a closure
public struct UserSessionClosure<UserID: Codable, Context: RequestContext & AuthRequestContext, User: Authenticatable>: SessionUserRepository {
    let getUserClosure: @Sendable (UserID, Context) async throws -> User?

    public func getUser(from id: UserID, context: Context) async throws -> User? {
        try await self.getUserClosure(id, context)
    }
}

/// Session authenticator
public struct SessionAuthenticator<Context: RequestContext & AuthRequestContext, Repository: SessionUserRepository>: AuthenticatorMiddleware where Context == Repository.Context {
    let users: Repository

    /// container for session objects
    let sessionStorage: SessionStorage

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
        getUser: @escaping @Sendable (Session, Context) async throws -> User?
    ) where Repository == UserSessionClosure<Session, Context, User> {
        self.users = UserSessionClosure(getUserClosure: getUser)
        self.sessionStorage = sessionStorage
    }

    public func authenticate(request: Request, context: Context) async throws -> Repository.User? {
        guard let session: Repository.UserID = try await self.sessionStorage.load(request: request) else { return nil }
        return try await self.users.getUser(from: session, context: context)
    }
}
