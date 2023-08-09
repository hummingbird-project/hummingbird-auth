//===----------------------------------------------------------------------===//
//
// This source file is part of the Hummingbird server framework project
//
// Copyright (c) 2021-2021 the Hummingbird authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See hummingbird/CONTRIBUTORS.txt for the list of Hummingbird authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Hummingbird
import NIOCore

/// Async version of session authenticator.
public protocol HBAsyncSessionAuthenticator: HBAsyncAuthenticator {
    associatedtype Value = Value
    associatedtype Session: Codable

    /// Convert Session object into authenticated user
    /// - Parameters:
    ///   - from: session
    ///   - request: request being processed
    /// - Returns: optional authenticated user
    func getValue(from: Session, request: HBRequest) async throws -> Value?

    /// Get Session object given request
    /// - Parameters:
    ///   - request: request being processed
    /// - Returns: Future holding optional authenticated user
    func getSession(request: HBRequest) async throws -> Session?
}

extension HBAsyncSessionAuthenticator {
    public func authenticate(request: HBRequest) async throws -> Value? {
        let session: Session? = try await request.session.load()
        guard let session = session else {
            return nil
        }
        return try await getValue(from: session, request: request)
    }

    public func getSession(request: HBRequest) async throws -> Session? {
        return try await request.session.load()
    }
}
