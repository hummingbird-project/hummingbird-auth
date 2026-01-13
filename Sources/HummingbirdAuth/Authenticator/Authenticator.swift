//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import Hummingbird
import NIOCore

/// Protocol for a middleware that checks if a request is authenticated.
///
/// Requires an `authenticate` function that returns authentication data when successful.
/// If it is unsuccessful then nil should be returned so middleware further down the
/// middleware chain can do authentication. If you don't want any further middleware to
/// run then throw an error.
///
/// To use an authenticator middleware it is required that your request context conform to
/// ``AuthRequestContext`` so the middleware can attach authentication data to
///  ``AuthRequestContext/identity-swift.property``.
///
/// A simple username, password authenticator could be implemented as follows. If the
/// authenticator is successful it returns a `User` struct, otherwise it returns `nil`.
///
/// ```swift
/// struct BasicAuthenticator<Context: AuthRequestContext>: AuthenticatorMiddleware {
///     func authenticate(request: Request, context: Context) async throws -> User? {
///         // Basic authentication info in the "Authorization" header, is accessible
///         // via request.headers.basic
///         guard let basic = request.headers.basic else { return nil }
///         // check if user exists in the database
///         guard let user = try await database.getUserWithUsername(basic.username) else {
///             return nil
///         }
///         // verify password against password hash stored in database. If valid
///         // return the user. HummingbirdAuth provides an implementation of Bcrypt
///         // This should be run on the thread pool as it is a long process.
///         return try await context.threadPool.runIfActive {
///             if Bcrypt.verify(basic.password, hash: user.passwordHash) {
///                 return user
///             }
///             return nil
///         }
///     }
/// }
/// ```
public protocol AuthenticatorMiddleware: RouterMiddleware where Context: AuthRequestContext<Identity> {
    /// Type to be authenticated
    associatedtype Identity: Sendable
    /// Called by middleware to see if request can authenticate.
    ///
    /// Should return an object if authenticated, return nil is not authenticated
    /// but want the request to be passed onto the next middleware or the router, or throw an error
    ///  if the request should not proceed any further
    func authenticate(request: Request, context: Context) async throws -> Identity?
}

extension AuthenticatorMiddleware {
    /// Calls `authenticate` and if it returns a valid object `login` with this object
    @inlinable
    public func handle(_ request: Request, context: Context, next: (Request, Context) async throws -> Response) async throws -> Response {
        if let authenticated = try await authenticate(request: request, context: context) {
            var context = context
            context.identity = authenticated
            return try await next(request, context)
        } else {
            return try await next(request, context)
        }
    }
}
