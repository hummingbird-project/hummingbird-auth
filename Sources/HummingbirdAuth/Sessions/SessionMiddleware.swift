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

public struct SessionMiddleware<Context: SessionRequestContext>: RouterMiddleware {
    let sessionStorage: SessionStorage
    let defaultSessionExpiration: Duration

    public init(sessionStorage: SessionStorage, sessionExpiration: Duration = .seconds(60 * 60 * 12)) {
        self.sessionStorage = sessionStorage
        self.defaultSessionExpiration = sessionExpiration
    }

    public func handle(_ request: Request, context: Context, next: (Request, Context) async throws -> Response) async throws -> Response {
        let sessionData = try await sessionStorage.load(as: SessionData<Context.Session>.self, request: request)
        if let sessionData {
            context.sessions.setSessionData(sessionData)
        }
        var response = try await next(request, context)
        let session = context.sessions.getSessionData()
        if let session {
            if session.edited {
                let expiresIn = session.expiresIn ?? self.defaultSessionExpiration
                do {
                    try await self.sessionStorage.update(session: session, expiresIn: expiresIn, request: request)
                } catch let error as SessionStorage.Error where error == .sessionDoesNotExist {
                    let cookie = try await self.sessionStorage.save(session: session, expiresIn: expiresIn)
                    response.headers[values: .setCookie].append(cookie.description)
                }
            }
        } else if sessionData != nil {
            // if we had a session and we don't anymore, set session to expire
            try await self.sessionStorage.update(session: session, expiresIn: .seconds(0), request: request)
        }
        return response
    }
}
