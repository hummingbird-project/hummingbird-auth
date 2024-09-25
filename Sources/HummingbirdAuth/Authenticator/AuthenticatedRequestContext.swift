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
import NIOCore

/// Protocol that all request contexts should conform to when they know a user is authentticated
public protocol AuthenticatedRequestContext: RequestContext {}

/// Implementation of a basic request context that asserts a user is authenticated.
/// It's anonymous because no information about the user is stored.
public struct AnonymousRequestContext: AuthenticatedRequestContext {
    /// core context
    public var coreContext: CoreRequestContextStorage

    ///  Initialize an `RequestContext`
    /// - Parameters:
    ///   - applicationContext: Context from Application that instigated the request
    ///   - channel: Channel that generated this request
    ///   - logger: Logger
    public init(source: Source) {
        self.coreContext = .init(source: source)
    }
}

/// Implementation of a basic request context that asserts a user is authenticated.
/// It's anonymous because no information about the user is stored.
public struct BasicAuthenticatedRequestContext<Identity: Authenticatable>: AuthenticatedRequestContext {
    public typealias Source = Never

    /// core context
    public var coreContext: CoreRequestContextStorage

    public let identity: Identity

    public init(coreContext: CoreRequestContextStorage, identity: Identity) {
        self.coreContext = coreContext
        self.identity = identity
    }
}
