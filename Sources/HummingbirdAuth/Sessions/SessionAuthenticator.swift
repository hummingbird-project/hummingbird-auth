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

import Hummingbird

/// Session authenticator
public protocol HBSessionAuthenticator: HBAuthenticator {
    /// authenticable value
    associatedtype Value = Value
    /// session object
    associatedtype Session: Codable

    /// container for session objects
    var sessionStorage: HBSessionStorage { get }

    /// Convert Session object into authenticated user
    /// - Parameters:
    ///   - from: session
    ///   - request: request being processed
    /// - Returns: Future holding optional authenticated user
    func getValue(from: Session, request: HBRequest, context: Context) async throws -> Value?
}

extension HBSessionAuthenticator {
    public func authenticate(request: HBRequest, context: Context) async throws -> Value? {
        guard let session: Session = try await self.sessionStorage.load(request: request) else { return nil }
        return try await getValue(from: session, request: request, context: context)
    }
}
