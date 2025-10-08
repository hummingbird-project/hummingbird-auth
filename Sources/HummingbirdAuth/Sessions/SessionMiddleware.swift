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

/// SessionStorage configuration
public struct SessionMiddlewareConfiguration: Sendable {
    /// Session cookie parameters
    public var sessionCookieParameters: SessionCookieParameters
    /// Prefix for key in key/value storage
    public var keyPrefix: String
    /// Default duration before session expires
    public var defaultSessionExpiration: Duration

    ///  Initialize SessionMiddlewareConfiguration
    /// - Parameters:
    ///   - sessionCookieParameters: Session Cookie parameters
    ///   - keyPrefix: Prefix for key in key/value storage
    ///   - defaultSessionExpiration: Default duration before session expires
    public init(
        sessionCookieParameters: SessionCookieParameters = .init(),
        keyPrefix: String = "hbs.",
        defaultSessionExpiration: Duration = .seconds(60 * 60 * 12)
    ) {
        self.sessionCookieParameters = sessionCookieParameters
        self.keyPrefix = keyPrefix
        self.defaultSessionExpiration = defaultSessionExpiration
    }

    /// Configuration for `SessionStorage` used by `SessionMiddleware`
    var sessionStorageConfiguration: SessionStorageConfiguration {
        .init(sessionCookieParameters: self.sessionCookieParameters, keyPrefix: self.keyPrefix)
    }
}

/// Middleware that extracts session data for a request and stores it in the context
///
/// The `SessionMiddleware` requires that the request context conform to ``SessionRequestContext``.
///
/// The middleware extracts the session data from storage based off the session cookie in the
/// request. If after returning from running the rest of the middleware chain the session data
/// is flagged as being edited it will save it into the session storage and in the case this is
/// a new session will set the "Set-Cookie" header.
public struct SessionMiddleware<Context: SessionRequestContext>: RouterMiddleware {
    /// Storage for session data
    let sessionStorage: SessionStorage<Context.Session>

    /// Default duration for a session token
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

    /// Initialize SessionMiddleware
    /// - Parameters:
    ///   - storage: Persist driver to use for storage
    ///   - sessionCookieParameters: Session cookie parameters
    ///   - defaultSessionExpiration: Default expiration for session data
    @available(*, deprecated, renamed: "init(storage:configuration:)")
    public init(
        storage: any PersistDriver,
        sessionCookieParameters: SessionCookieParameters,
        defaultSessionExpiration: Duration = .seconds(60 * 60 * 12)
    ) {
        self.sessionStorage = .init(storage, configuration: .init(sessionCookieParameters: sessionCookieParameters))
        self.defaultSessionExpiration = defaultSessionExpiration
    }

    /// Initialize SessionMiddleware
    /// - Parameters:
    ///   - storage: Persist driver to use for storage
    ///   - sessionCookieParameters: Session cookie parameters
    ///   - defaultSessionExpiration: Default expiration for session data
    public init(
        storage: any PersistDriver,
        configuration: SessionMiddlewareConfiguration
    ) {
        self.sessionStorage = .init(storage, configuration: configuration.sessionStorageConfiguration)
        self.defaultSessionExpiration = configuration.defaultSessionExpiration
    }

    ///  Initialize Session Middleware with existing session storage
    /// - Parameters:
    ///   - sessionStorage: Session storage
    ///   - defaultSessionExpiration: Default expiration for session data
    public init(sessionStorage: SessionStorage<Context.Session>, defaultSessionExpiration: Duration = .seconds(60 * 60 * 12)) {
        self.sessionStorage = sessionStorage
        self.defaultSessionExpiration = defaultSessionExpiration
    }

    ///  Session Middleware handler
    public func handle(_ request: Request, context: Context, next: (Request, Context) async throws -> Response) async throws -> Response {
        var originalSessionData: Context.Session? = nil
        var removeSession = false
        do {
            originalSessionData = try await self.sessionStorage.load(request: request)
        } catch let error as SessionStorage<Context.Session>.Error where error == .sessionInvalidType {
            context.logger.trace("Failed to convert session data")
            removeSession = true
        } catch {
            context.logger.debug("Failed to load session data")
        }
        if let originalSessionData {
            context.sessions.sessionData = SessionData(
                value: originalSessionData,
                expiresIn: nil
            )
        }
        var response = try await next(request, context)
        let sessionData = context.sessions.sessionData
        if let sessionData {
            // if session has been edited then store new session
            if sessionData.edited {
                do {
                    if let cookie = try await self.sessionStorage.updateAndCreateCookie(
                        session: sessionData.object,
                        expiresIn: sessionData.expiresIn,
                        request: request
                    ) {
                        response.headers[values: .setCookie].append(cookie.description)
                    }
                } catch let error as SessionStorage<Context.Session>.Error where error == .sessionDoesNotExist {
                    let cookie = try await self.sessionStorage.save(
                        session: sessionData.object,
                        expiresIn: sessionData.expiresIn ?? self.defaultSessionExpiration
                    )
                    response.headers[values: .setCookie].append(cookie.description)
                }
            }
        } else if originalSessionData != nil || removeSession {
            // if we had a session and we don't anymore, set session to expire
            let cookie = try await self.sessionStorage.delete(request: request)
            // As the session and cookie expiration has been updated, set the "Set-Cookie" header
            response.headers[values: .setCookie].append(cookie.description)
        }
        return response
    }
}
