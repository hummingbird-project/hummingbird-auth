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

/// Middleware returning 401 for unauthenticated requests
public struct IsAuthenticatedMiddleware<Auth: Authenticatable, Context: AuthRequestContext>: RouterMiddleware {
    public init(_: Auth.Type) {}

    public func handle(_ request: Request, context: Context, next: (Request, Context) async throws -> Response) async throws -> Response { guard context.auth.has(Auth.self) else { throw HTTPError(.unauthorized) }
        return try await next(request, context)
    }
}
