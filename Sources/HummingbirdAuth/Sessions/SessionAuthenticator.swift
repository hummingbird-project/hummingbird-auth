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

    /// Convert Session object into authenticated user
    /// - Parameters:
    ///   - from: session
    ///   - request: request being processed
    /// - Returns: Future holding optional authenticated user
    func getValue(from: Session, request: HBRequest) -> EventLoopFuture<Value?>

    /// Get Session object given request
    /// - Parameters:
    ///   - request: request being processed
    /// - Returns: Future holding optional authenticated user
    func getSession(request: HBRequest) -> EventLoopFuture<Session?>
}

extension HBSessionAuthenticator {
    public func authenticate(request: HBRequest) -> EventLoopFuture<Value?> {
        return self.getSession(request: request).flatMap { (session: Session?) in
            // check if session exists.
            guard let session = session else {
                return request.success(nil)
            }
            // find authenticated user from session
            return getValue(from: session, request: request)
        }
    }

    public func getSession(request: HBRequest) -> EventLoopFuture<Session?> {
        return request.session.load()
    }
}
