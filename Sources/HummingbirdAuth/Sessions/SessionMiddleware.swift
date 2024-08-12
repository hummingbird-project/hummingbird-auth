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
@available(*, deprecated, message: "Use SessionAuthenticator instead.")
public protocol SessionMiddleware: AuthenticatorMiddleware {
    /// authenticable value
    associatedtype Value = Value
    /// session object
    associatedtype Session: Codable

    /// container for session objects
    var sessionStorage: SessionStorage { get }

    /// Convert Session object into authenticated user
    /// - Parameters:
    ///   - from: session
    ///   - request: request being processed
    /// - Returns: Future holding optional authenticated user
    func getValue(from: Session, request: Request, context: Context) async throws -> Value?
}

@available(*, deprecated, message: "Use SessionAuthenticator instead.")
extension SessionMiddleware {
    public func authenticate(request: Request, context: Context) async throws -> Value? {
        guard let session: Session = try await self.sessionStorage.load(request: request) else { return nil }
        return try await getValue(from: session, request: request, context: context)
    }
}
