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

public struct ClosureAuthenticator<
    Identity: Authenticatable,
    Context: AuthRequestContext<Identity>
>: AuthenticatorMiddleware {
    let closure: @Sendable (Request, Context) async throws -> Identity?

    public init(_ closure: @escaping @Sendable (Request, Context) async throws -> Identity?) {
        self.closure = closure
    }

    public func authenticate(request: Request, context: Context) async throws -> Identity? {
        return try await self.closure(request, context)
    }
}
