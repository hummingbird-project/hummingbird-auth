//===----------------------------------------------------------------------===//
//
// This source file is part of the Hummingbird server framework project
//
// Copyright (c) 2021-2022 the Hummingbird authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See hummingbird/CONTRIBUTORS.txt for the list of Hummingbird authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import ExtrasBase64
import Hummingbird

/// Stores session data
public struct SessionStorage: Sendable {
    /// SessionStorage Errors
    public struct Error: Swift.Error, Equatable {
        enum ErrorType {
            case sessionDoesNotExist
        }

        let type: ErrorType
        private init(_ type: ErrorType) {
            self.type = type
        }

        /// Session does not exist
        public static var sessionDoesNotExist: Self { .init(.sessionDoesNotExist) }
    }

    let sessionCookie: String

    /// Initialize session storage
    public init(_ storage: any PersistDriver, sessionCookie: String = "SESSION_ID") {
        self.storage = storage
        self.sessionCookie = sessionCookie
    }

    /// save new or exising session
    ///
    /// Saving a new session will create a new session id and returns a cookie setting
    /// the session id. You need to then return a response including this cookie. You
    /// can either create an ``HummingbirdCore/Response`` directly or use ``Hummingbird/EditedResponse`` to
    /// generate the response from another type.
    /// ```swift
    /// let cookie = try await sessionStorage.save(session: session, expiresIn: .seconds(600))
    /// var response = EditedResponse(response: responseGenerator)
    /// response.setCookie(cookie)
    /// return response
    /// ```
    /// If you know a session already exists it is preferable to use
    /// ``SessionStorage/update(session:expiresIn:request:)``.
    public func save(session: some Codable, expiresIn: Duration) async throws -> Cookie {
        let sessionId = Self.createSessionId()
        // prefix with "hbs."
        try await self.storage.set(
            key: "hbs.\(sessionId)",
            value: session,
            expires: expiresIn
        )
        return .init(name: self.sessionCookie, value: sessionId, path: "/")
    }

    /// update existing session
    ///
    /// If session does not exist then a `sessionDoesNotExist` error will be thrown
    public func update(session: some Codable, expiresIn: Duration, request: Request) async throws {
        guard let sessionId = self.getId(request: request) else {
            throw Error.sessionDoesNotExist
        }
        // prefix with "hbs."
        try await self.storage.set(
            key: "hbs.\(sessionId)",
            value: session,
            expires: expiresIn
        )
    }

    /// load session
    public func load<Session: Codable>(as: Session.Type = Session.self, request: Request) async throws -> Session? {
        guard let sessionId = getId(request: request) else { return nil }
        // prefix with "hbs."
        return try await self.storage.get(
            key: "hbs.\(sessionId)",
            as: Session.self
        )
    }

    /// delete session
    public func delete(request: Request) async throws {
        guard let sessionId = getId(request: request) else { return }
        // prefix with "hbs."
        return try await self.storage.remove(
            key: "hbs.\(sessionId)"
        )
    }

    /// Get session id gets id from request
    func getId(request: Request) -> String? {
        guard let sessionCookie = request.cookies[self.sessionCookie]?.value else { return nil }
        return String(sessionCookie)
    }

    /// create a session id
    static func createSessionId() -> String {
        let bytes: [UInt8] = (0..<32).map { _ in UInt8.random(in: 0...255) }
        return String(base64Encoding: bytes)
    }

    // This is wrapped in an unsafe storage wrapper because I cannot conform `PersistDriver`
    // to `Sendable` at this point because Redis and Fluent types do not currently conform to
    // `Sendable` when it should be possible for this to be the case.
    let storage: any PersistDriver
}
