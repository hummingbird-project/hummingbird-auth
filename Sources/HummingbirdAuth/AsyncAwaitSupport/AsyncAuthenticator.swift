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

#if compiler(>=5.5) && canImport(_Concurrency)

import NIOCore
import Hummingbird

/// Authenticators are middleware that are used to check if a request is authenticated and then augment the request with the
/// authentication data. This version uses an async/await style method for authentication
@available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *)
public protocol HBAsyncAuthenticator: HBAuthenticator {
    associatedtype Value = Value
    func authenticate(request: HBRequest) async throws -> Value?
}

@available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *)
extension HBAsyncAuthenticator {
    public func authenticate(request: HBRequest) -> EventLoopFuture<Value?> {
        let promise = request.eventLoop.makePromise(of: Value?.self)
        promise.completeWithTask {
            try await authenticate(request: request)
        }
        return promise.futureResult
    }
}

#endif // compiler(>=5.5) && canImport(_Concurrency)
