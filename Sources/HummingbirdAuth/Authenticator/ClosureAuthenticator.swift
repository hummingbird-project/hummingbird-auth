//===----------------------------------------------------------------------===//
//
// This source file is part of the Hummingbird server framework project
//
// Copyright (c) 2021-2023 the Hummingbird authors
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

public struct ClosureAuthenticator<Context: AuthRequestContext, Value: Authenticatable>: AuthenticatorMiddleware {
    let closure: @Sendable (Request, Context) async throws -> Value?

    public init(_ closure: @escaping @Sendable (Request, Context) async throws -> Value?) {
        self.closure = closure
    }

    public func authenticate(request: Request, context: Context) async throws -> Value? {
        return try await self.closure(request, context)
    }
}