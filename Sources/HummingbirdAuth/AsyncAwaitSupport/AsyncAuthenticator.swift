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

/// Async version of Middleware to check if a request is authenticated and then augment the request with
/// authentication data.
public protocol HBAsyncAuthenticator: HBAuthenticator {
    associatedtype Value = Value
    func authenticate(request: HBRequest) async throws -> Value?
}

extension HBAsyncAuthenticator {
    public func authenticate(request: HBRequest) -> EventLoopFuture<Value?> {
        let promise = request.eventLoop.makePromise(of: Value?.self)
        promise.completeWithTask {
            try await authenticate(request: request)
        }
        return promise.futureResult
    }
}
