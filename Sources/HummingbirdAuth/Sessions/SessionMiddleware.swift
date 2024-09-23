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

/// Middleware that extracts session data for a request and stores it in the context
///
/// The `SessionMiddleware` requires that the request context conform to ``SessionRequestContext``.
///
/// The middleware extracts the session data from storage based off the session cookie in the
/// request. If after returning from running the rest of the middleware chain the session data
/// is flagged as being edited it will save it into the session storage and in the case this is
/// a new session will set the "Set-Cookie" header.
public struct SessionMiddleware<Context: SessionRequestContext>: RouterMiddleware {
    /// storage for session data
    let sessionStorage: SessionStorage
    /// default duration for a session token
    let defaultSessionExpiration: Duration

    /// Initialize SessionMiddleware
    /// - Parameters:
    ///   - storage: Persist driver to use for storage
    ///   - sessionCookie: Session cookie name
    ///   - defaultSessionExpiration: Default expiration for session data
    public init(storage: any PersistDriver, sessionCookie: String = "SESSION_ID", defaultSessionExpiration: Duration = .seconds(60 * 60 * 12)) {
        self.sessionStorage = .init(storage, sessionCookie: sessionCookie)
        self.defaultSessionExpiration = defaultSessionExpiration
    }

    ///  Initialize Session Middleware
    /// - Parameters:
    ///   - sessionStorage: Session storage
    ///   - defaultSessionExpiration: Default expiration for session data
    public init(sessionStorage: SessionStorage, defaultSessionExpiration: Duration = .seconds(60 * 60 * 12)) {
        self.sessionStorage = sessionStorage
        self.defaultSessionExpiration = defaultSessionExpiration
    }

    ///  Session Middleware handler
    public func handle(_ request: Request, context: Context, next: (Request, Context) async throws -> Response) async throws -> Response {
        let originalSessionData = try await sessionStorage.load(as: SessionData<Context.Session>.self, request: request)
        if let originalSessionData {
            context.sessions.sessionData = originalSessionData
        }
        var response = try await next(request, context)
        let sessionData = context.sessions.sessionData
        if let sessionData {
            // if session has been edited then store new session
            if sessionData.edited {
                let expiresIn = sessionData.expiresIn ?? self.defaultSessionExpiration
                do {
                    try await self.sessionStorage.update(session: sessionData, expiresIn: expiresIn, request: request)
                } catch let error as SessionStorage.Error where error == .sessionDoesNotExist {
                    let cookie = try await self.sessionStorage.save(session: sessionData, expiresIn: expiresIn)
                    // this is a new session so set the "Set-Cookie" header
                    response.headers[values: .setCookie].append(cookie.description)
                }
            }
        } else if originalSessionData != nil {
            // if we had a session and we don't anymore, set session to expire
            try await self.sessionStorage.update(session: sessionData, expiresIn: .seconds(0), request: request)
        }
        return response
    }
}
