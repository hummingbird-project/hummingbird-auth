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

import Foundation
import Hummingbird
import NIOConcurrencyHelpers

/// Session data
@dynamicMemberLookup
public struct SessionData<Session: Sendable & Codable>: Codable, Sendable {
    @usableFromInline
    var object: Session
    @usableFromInline
    var edited: Bool
    /// When session will expire
    public var expiresIn: Duration?

    @usableFromInline
    init(value: Session, expiresIn: Duration?) {
        self.object = value
        self.edited = true
        self.expiresIn = expiresIn
    }

    /// Codable decode initializer
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        self.object = try container.decode(Session.self)
        self.edited = false
        self.expiresIn = nil
    }

    /// Codable encode
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.object)
    }

    /// Dynamic member lookup. Sets `edited` state if value in `object` is mutated.
    @inlinable
    public subscript<T>(dynamicMember keyPath: WritableKeyPath<Session, T>) -> T {
        get {
            self.object[keyPath: keyPath]
        }
        set {
            self.object[keyPath: keyPath] = newValue
            self.edited = true
        }
    }
}

/// Session context
///
/// Holds reference to session data protected by a lock to avoid concurrent access
public struct SessionContext<Session: Sendable & Codable>: Sendable {
    @usableFromInline
    var sessionData: SessionData<Session>?

    /// Initialize `SessionContext`
    @inlinable
    public init() {
        self.sessionData = nil
    }

    ///  Set session data
    /// - Parameters:
    ///   - session: Session data
    ///   - expiresIn: How long before session data expires
    @inlinable
    public mutating func setSession(_ session: Session, expiresIn: Duration? = nil) {
        self.sessionData = .init(value: session, expiresIn: expiresIn)
    }

    ///  Clear session data
    @inlinable
    public mutating func clearSession() {
        self.sessionData = nil
    }

    /// Get a copy of the session data
    @inlinable
    public var session: Session? { sessionData?.object }
}

/// Protocol for RequestContext that stores session data
///
/// The `Session` associatedtype is the data stored in your session. This could be
/// as simple as a `UUID`` that is used to extract a user from a database to a
/// struct containing support for multiple authentication flows.
public protocol SessionRequestContext<Session>: RequestContext {
    associatedtype Session: Sendable & Codable
    var sessions: SessionContext<Session> { get set }
}

/// Implementation of a basic request context that supports session storage and authenticators
public struct BasicSessionRequestContext<Session>: AuthRequestContext, SessionRequestContext, RequestContext where Session: Sendable & Codable {
    /// core context
    public var coreContext: CoreRequestContextStorage
    /// Login cache
    public var auth: LoginCache
    /// Session
    public var sessions: SessionContext<Session>

    ///  Initialize an `RequestContext`
    /// - Parameters:
    ///   - applicationContext: Context from Application that instigated the request
    ///   - channel: Channel that generated this request
    ///   - logger: Logger
    public init(source: Source) {
        self.coreContext = .init(source: source)
        self.auth = .init()
        self.sessions = .init()
    }
}
