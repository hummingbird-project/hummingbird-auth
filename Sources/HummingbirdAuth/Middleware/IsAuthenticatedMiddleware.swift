//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import Hummingbird

/// Middleware returning 401 for unauthenticated requests
public struct IsAuthenticatedMiddleware<Context: AuthRequestContext>: RouterMiddleware {
    public init() {}

    public func handle(_ request: Request, context: Context, next: (Request, Context) async throws -> Response) async throws -> Response {
        guard context.identity != nil else {
            throw HTTPError(.unauthorized)
        }
        return try await next(request, context)
    }
}
