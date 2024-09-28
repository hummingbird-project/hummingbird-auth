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
///
/// The `SessionAuthenticator` needs to have the ``SessionMiddleware`` before it in the middleware
/// chain to extract session information for the request
public struct BasicSessionAuthenticator<
    InputContext: SessionRequestContext,
    Repository: UserSessionRepository
>: OptionalAuthenticatorMiddleware where InputContext.Session == Repository.Identifier {
    public typealias InputContext = InputContext

    public typealias Value = Repository.User
    public typealias Input = Request
    public typealias Output = Response

    /// User repository
    public let users: Repository

    /// Initialize SessionAuthenticator middleware
    /// - Parameters:
    ///   - users: User repository
    ///   - context: Request context type
    public init(users: Repository, context: InputContext.Type = InputContext.self) {
        self.users = users
    }

    /// Initialize SessionAuthenticator middleware
    /// - Parameters:
    ///   - context: Request context type
    ///   - getUser: Closure returning user type from session id
    public init<User: Authenticatable, Session>(
        context: InputContext.Type = InputContext.self,
        getUser: @escaping @Sendable (Session, UserRepositoryContext) async throws -> User?
    ) where Repository == UserSessionClosureRepository<Session, User> {
        self.users = UserSessionClosureRepository(getUser)
    }

    @inlinable
    public func authenticate(request: Request, context: InputContext) async throws -> Repository.User? {
        if let session = context.sessions.session {
            return try await self.users.getUser(from: session, context: .init(logger: context.logger))
        } else {
            return nil
        }
    }
}
