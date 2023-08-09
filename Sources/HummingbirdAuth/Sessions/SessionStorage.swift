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
import HummingbirdFoundation

/// Stores session data
public struct HBSessionStorage {
    /// HBSessionStorage Errors
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

    let sessionID: SessionIDStorage

    // enum defining where to store a session id
    public enum SessionIDStorage: Sendable {
        case cookie(String)
        case header(String)
    }

    /// Initialize session storage
    init(_ storage: HBPersistDriver, sessionID: SessionIDStorage = .cookie("SESSION_ID")) {
        self.storage = storage
        self.sessionID = sessionID
    }

    /// save new or exising session
    ///
    /// Saving a new session will create a new session id and save that to the
    /// response. Thus a route that uses `save` needs to have the `.editResponse`
    /// option set. If you know the session already exists consider using
    /// `update` instead.
    public func save<Session: Codable>(session: Session, expiresIn: TimeAmount, request: HBRequest) -> EventLoopFuture<Void> {
        let sessionId = self.getId(request: request) ?? Self.createSessionId()
        // prefix with "hbs."
        return self.storage.set(
            key: "hbs.\(sessionId)",
            value: session,
            expires: expiresIn,
            request: request
        ).map { _ in self.setId(sessionId, request: request) }
    }

    /// update existing session
    ///
    /// If session does not exist then this function will do nothing
    public func update<Session: Codable>(session: Session, expiresIn: TimeAmount, request: HBRequest) -> EventLoopFuture<Void> {
        guard let sessionId = self.getId(request: request) else {
            return request.failure(Error.sessionDoesNotExist)
        }
        // prefix with "hbs."
        return self.storage.set(
            key: "hbs.\(sessionId)",
            value: session,
            expires: expiresIn,
            request: request
        )
    }

    /// load session
    public func load<Session: Codable>(as: Session.Type = Session.self, request: HBRequest) -> EventLoopFuture<Session?> {
        guard let sessionId = getId(request: request) else { return request.success(nil) }
        // prefix with "hbs."
        return self.storage.get(
            key: "hbs.\(sessionId)",
            as: Session.self,
            request: request
        )
    }

    /// Get session id gets id from request
    func getId(request: HBRequest) -> String? {
        switch self.sessionID {
        case .cookie(let cookie):
            guard let sessionCookie = request.cookies[cookie]?.value else { return nil }
            return String(sessionCookie)
        case .header(let header):
            guard let sessionHeader = request.headers[header].first else { return nil }
            return sessionHeader
        }
    }

    /// set session id on response
    func setId(_ id: String, request: HBRequest) {
        precondition(
            request.extensions.get(\.response) != nil,
            "Saving a session involves editing the response via HBRequest.response which cannot be done outside of a route without the .editResponse option set"
        )
        switch self.sessionID {
        case .cookie(let cookie):
            request.response.setCookie(.init(name: cookie, value: id))
        case .header(let header):
            request.response.headers.replaceOrAdd(name: header, value: id)
        }
    }

    /// create a session id
    static func createSessionId() -> String {
        let bytes: [UInt8] = (0..<32).map { _ in UInt8.random(in: 0...255) }
        return String(base64Encoding: bytes)
    }

    let storage: HBPersistDriver
}

extension HBSessionStorage {
    /// save new or exising session
    ///
    /// Saving a new session will create a new session id and save that to the
    /// response. Thus a route that uses `save` needs to have the `.editResponse`
    /// option set. If you know the session already exists consider using
    /// `update` instead.
    public func save<Session: Codable>(session: Session, expiresIn: TimeAmount, request: HBRequest) async throws {
        let sessionId = Self.createSessionId()
        // prefix with "hbs."
        try await self.storage.set(
            key: "hbs.\(sessionId)",
            value: session,
            expires: expiresIn,
            request: request
        ).get()
        self.setId(sessionId, request: request)
    }

    /// update existing session
    ///
    /// If session does not exist then a `sessionDoesNotExist` error will be thrown
    public func update<Session: Codable>(session: Session, expiresIn: TimeAmount, request: HBRequest) async throws {
        guard let sessionId = self.getId(request: request) else {
            throw Error.sessionDoesNotExist
        }
        // prefix with "hbs."
        try await self.storage.set(
            key: "hbs.\(sessionId)",
            value: session,
            expires: expiresIn,
            request: request
        ).get()
    }

    /// load session
    public func load<Session: Codable>(as: Session.Type = Session.self, request: HBRequest) async throws -> Session? {
        guard let sessionId = getId(request: request) else { return nil }
        // prefix with "hbs."
        return try await self.storage.get(
            key: "hbs.\(sessionId)",
            as: Session.self,
            request: request
        ).get()
    }
}
