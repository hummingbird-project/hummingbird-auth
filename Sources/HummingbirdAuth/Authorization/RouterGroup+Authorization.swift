//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import Hummingbird

extension RouterGroup where Context: AuthRequestContext {

    /// Add authorization to this route group.
    ///
    /// All policies in the block must pass (AND semantics). Use ``anyOf(_:_:)``
    /// or ``allOf(_:_:)`` inside the block for OR / nested AND:
    ///
    /// ```swift
    /// router.group()
    ///     .add(middleware: MyAuthenticator())
    ///     .authorized {
    ///         RolePolicy("admin")
    ///         PermissionPolicy("posts:write")
    ///     }
    ///     .get("dashboard") { _, _ in ... }
    ///
    /// // OR semantics
    /// .authorized {
    ///     anyOf(RolePolicy("admin"), RolePolicy("moderator"))
    /// }
    /// ```
    @discardableResult
    public func authorized<Policy: AuthorizationPolicy>(
        @AllOfBuilder<Context.Identity> _ build: () -> Policy
    ) -> RouterGroup<Context> where Policy.Identity == Context.Identity {
        self.add(middleware: AuthorizationPolicyMiddleware(build()))
    }

    /// Add authorization with a custom denial error.
    ///
    /// ```swift
    /// .authorized(deniedError: HTTPError(.notFound)) {
    ///     RolePolicy("admin")
    /// }
    /// ```
    @discardableResult
    public func authorized<Policy: AuthorizationPolicy, DeniedError: HTTPResponseError & Sendable>(
        deniedError: DeniedError,
        @AllOfBuilder<Context.Identity> _ build: () -> Policy
    ) -> RouterGroup<Context> where Policy.Identity == Context.Identity {
        self.add(middleware: AuthorizationPolicyMiddleware(build(), deniedError: deniedError))
    }
}
