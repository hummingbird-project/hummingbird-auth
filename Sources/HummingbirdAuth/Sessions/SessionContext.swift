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

@dynamicMemberLookup
public struct SessionData<Session: Sendable & Codable>: Codable, Sendable {
    @usableFromInline
    var object: Session
    @usableFromInline
    var edited: Bool

    public init(value: Session) {
        self.object = value
        self.edited = true
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        self.object = try container.decode(Session.self)
        self.edited = false
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.object)
    }

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

public struct SessionContext<Session: Sendable & Codable>: Sendable {
    @usableFromInline
    let _storage: NIOLockedValueBox<SessionData<Session>?>

    @inlinable
    public init() {
        self._storage = .init(nil)
    }

    public func setSession(_ session: Session) {
        self._storage.withLockedValue {
            $0 = .init(value: session)
        }
    }

    public func clearSession() {
        self._storage.withLockedValue {
            $0 = nil
        }
    }

    public var session: Session? { self._storage.withLockedValue { $0?.object } }

    public func withLockedSession<Value>(_ mutate: (inout SessionData<Session>?) -> Value) -> Value {
        self._storage.withLockedValue {
            mutate(&$0)
        }
    }

    func setSessionData(_ sessionData: SessionData<Session>) {
        self._storage.withLockedValue {
            $0 = sessionData
        }
    }

    func getSessionData() -> SessionData<Session>? {
        self._storage.withLockedValue { $0 }
    }
}

public protocol SessionRequestContext<Session>: RequestContext {
    associatedtype Session: Sendable & Codable
    var sessions: SessionContext<Session> { get }
}

/// Implementation of a basic request context that supports everything the Hummingbird library needs
public struct BasicSessionRequestContext<Session>: AuthRequestContext, SessionRequestContext, RequestContext where Session: Sendable & Codable {
    /// core context
    public var coreContext: CoreRequestContextStorage
    /// Login cache
    public var auth: LoginCache
    /// Session
    public let sessions: SessionContext<Session>

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
