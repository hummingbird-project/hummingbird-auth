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
import NIOConcurrencyHelpers

/// Protocol that all request contexts should conform to if they want to support
/// authentication middleware
public protocol AuthRequestContext<Identity>: RequestContext {
    associatedtype Identity: Authenticatable

    /// The authenticated identity
    var auth: AuthContainer<Identity> { get set }
}

extension AuthRequestContext {
    public var identity: Identity? {
        get { auth.identity }
        nonmutating set { auth.identity = newValue }
    }
}

public struct AuthContainer<Identity: Authenticatable>: Sendable {
    private let _identity: NIOLockedValueBox<Identity?>

    public var identity: Identity? {
        get { _identity.withLockedValue { $0 } }
        nonmutating set { _identity.withLockedValue { $0 = newValue } }
    }

    public init(_ identity: Identity? = nil) {
        self._identity = .init(identity)
    }
}

/// Implementation of a basic request context that supports authenticators
public struct BasicAuthRequestContext<Identity: Authenticatable>: AuthRequestContext, RequestContext {
    /// core context
    public var coreContext: CoreRequestContextStorage
    /// The authenticated identity
    public var auth: AuthContainer<Identity>

    ///  Initialize an `RequestContext`
    /// - Parameters:
    ///   - applicationContext: Context from Application that instigated the request
    ///   - channel: Channel that generated this request
    ///   - logger: Logger
    public init(source: Source) {
        self.coreContext = .init(source: source)
        self.auth = .init()
    }
}
