//===----------------------------------------------------------------------===//
//
// This source file is part of the Hummingbird server framework project
//
// Copyright (c) 2023 the Hummingbird authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See hummingbird/CONTRIBUTORS.txt for the list of Hummingbird authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Hummingbird
import Logging
import NIOConcurrencyHelpers
import NIOCore

/// Protocol that all request contexts should conform to if they want to support
/// authentication middleware
public protocol AuthRequestContext<Identity>: RequestContext {
    associatedtype Identity: Sendable

    /// The authenticated identity
    var identity: Identity? { get set }
}

/// Implementation of a basic request context that supports authenticators
public struct BasicAuthRequestContext<Identity: Sendable>: AuthRequestContext, RequestContext {
    /// core context
    public var coreContext: CoreRequestContextStorage
    /// The authenticated identity
    public var identity: Identity?

    ///  Initialize an `RequestContext`
    /// - Parameters:
    ///   - applicationContext: Context from Application that instigated the request
    ///   - channel: Channel that generated this request
    ///   - logger: Logger
    public init(source: Source) {
        self.coreContext = .init(source: source)
        self.identity = nil
    }
}
