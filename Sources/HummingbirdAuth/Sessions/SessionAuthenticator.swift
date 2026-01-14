//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import Hummingbird

/// Session authenticator
///
/// The `SessionAuthenticator` needs to have the ``SessionMiddleware`` before it in the middleware
/// chain to extract session information for the request
public struct SessionAuthenticator<
    Context: AuthRequestContext & SessionRequestContext,
    Repository: UserSessionRepository<Context.Session, Context.Identity>
>: AuthenticatorMiddleware {
    public typealias Identity = Context.Identity

    /// User repository
    public let users: Repository

    /// Initialize SessionAuthenticator middleware
    /// - Parameters:
    ///   - users: User repository
    ///   - context: Request context type
    public init(users: Repository, context: Context.Type = Context.self) {
        self.users = users
    }

    /// Initialize SessionAuthenticator middleware
    /// - Parameters:
    ///   - context: Request context type
    ///   - getUser: Closure returning user type from session id
    public init<Session>(
        context: Context.Type = Context.self,
        getUser: @escaping @Sendable (Session, UserRepositoryContext) async throws -> Context.Identity?
    ) where Repository == UserSessionClosureRepository<Session, Identity> {
        self.users = UserSessionClosureRepository(getUser)
    }

    @inlinable
    public func authenticate(request: Request, context: Context) async throws -> Repository.User? {
        if let session = context.sessions.session {
            return try await self.users.getUser(from: session, context: .init(logger: context.logger))
        } else {
            return nil
        }
    }
}
