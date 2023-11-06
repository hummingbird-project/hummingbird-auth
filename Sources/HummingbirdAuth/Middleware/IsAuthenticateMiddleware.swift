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

/// Middleware returning 404 for unauthenticated requests
public struct IsAuthenticatedMiddleware<Auth: HBAuthenticatable, Context: HBAuthRequestContextProtocol>: HBMiddleware {
    public init(_: Auth.Type) {}

    public func apply(to request: HBRequest, context: Context, next: any HBResponder<Context>) async throws -> HBResponse {
        guard context.auth.has(Auth.self) else { throw HBHTTPError(.unauthorized) }
        return try await next.respond(to: request, context: context)
    }
}
