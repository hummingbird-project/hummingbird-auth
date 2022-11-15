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

public protocol HBSessionAuthenticator: HBAuthenticator {
    associatedtype Value = Value
    associatedtype Session: Codable

    func getValue(from: Session, request: HBRequest) -> EventLoopFuture<Value?>
}

extension HBSessionAuthenticator {
    public func authenticate(request: HBRequest) -> EventLoopFuture<Value?> {
        // check if session exists.
        return request.session.load().flatMap { (session: Session?) in
            guard let session = session else {
                return request.success(nil)
            }
            // find user from session
            return getValue(from: session, request: request)
        }
    }
}
