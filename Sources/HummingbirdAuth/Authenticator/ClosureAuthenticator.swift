//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import Hummingbird
import NIOCore

/// Authenticator that uses a closure to return authentication state
public struct ClosureAuthenticator<
    Context: AuthRequestContext
>: AuthenticatorMiddleware {
    public typealias Identity = Context.Identity

    let closure: @Sendable (Request, Context) async throws -> Context.Identity?

    public init(_ closure: @escaping @Sendable (Request, Context) async throws -> Context.Identity?) {
        self.closure = closure
    }

    public func authenticate(request: Request, context: Context) async throws -> Context.Identity? {
        try await self.closure(request, context)
    }
}
