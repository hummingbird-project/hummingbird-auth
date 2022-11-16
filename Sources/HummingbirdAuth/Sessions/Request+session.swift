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
import Foundation
import Hummingbird
import HummingbirdFoundation

/// Manage session ids and associated data
public struct SessionManager {
    internal static var sessionIDStorage: SessionIDStorage = .cookie("SESSION_ID")

    // enum defining where to store a session id
    public enum SessionIDStorage {
        case cookie(String)
        case header(String)
    }

    /// save session
    public func save<Session: Codable>(session: Session, expiresIn: TimeAmount) -> EventLoopFuture<Void> {
        let sessionId = Self.createSessionId()
        // prefix with "hbs."
        return self.request.persist.set(
            key: "hbs.\(sessionId)",
            value: session,
            expires: expiresIn
        ).map { _ in setId(sessionId) }
    }

    /// load session
    public func load<Session: Codable>(as: Session.Type = Session.self) -> EventLoopFuture<Session?> {
        guard let sessionId = getId() else { return self.request.success(nil) }
        // prefix with "hbs."
        return self.request.persist.get(key: "hbs.\(sessionId)", as: Session.self)
    }

    /// Get session id gets id from request
    public func getId() -> String? {
        switch Self.sessionIDStorage {
        case .cookie(let cookie):
            guard let sessionCookie = request.cookies[cookie]?.value else { return nil }
            return String(sessionCookie)
        case .header(let header):
            guard let sessionHeader = request.headers[header].first else { return nil }
            return sessionHeader
        }
    }

    /// set session id on response
    public func setId(_ id: String) {
        switch Self.sessionIDStorage {
        case .cookie(let cookie):
            self.request.response.setCookie(.init(name: cookie, value: id))
        case .header(let header):
            self.request.response.headers.replaceOrAdd(name: header, value: id)
        }
    }

    /// create a session id
    public static func createSessionId() -> String {
        let bytes: [UInt8] = (0..<32).map { _ in UInt8.random(in: 0...255) }
        return String(base64Encoding: bytes)
    }

    let request: HBRequest
}

extension HBRequest {
    /// access session info
    public var session: SessionManager { return .init(request: self) }
}
