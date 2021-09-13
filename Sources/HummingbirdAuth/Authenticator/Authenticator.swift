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
import NIO

/// Protocol for objects that can be returned by an `HBAuthenticator`.
public protocol HBAuthenticatable {}

/// Authenticators are middleware that are used to check if a request is authenticated and then augment the request with the
/// authentication data.
///
/// Authenticators should conform to protocol `HBAuthenticator`. This requires you implement the function
/// `authenticate(request: HBRequest) -> EventLoopFuture<Value?>` where `Value` is an
/// object conforming to the protocol `HBAuthenticatable`.
///
/// A simple username, password authenticator could be implemented as follows. If the authenticator is successful
/// it returns a `User` struct, otherwise it returns `nil`.
///
/// ```swift
/// struct BasicAuthenticator: HBAuthenticator {
///     func authenticate(request: HBRequest) -> EventLoopFuture<User?> {
///         // Basic authentication info in the "Authorization" header, is accessible
///         // via request.auth.basic
///         guard let basic = request.auth.basic else { return request.success(nil) }
///         // check if user exists in the database and then verify the entered password
///         // against the one stored in the database. If it is correct then login in user
///         return database.getUserWithUsername(basic.username).map { user -> User? in
///             // did we find a user
///             guard let user = user else { return nil }
///             // verify password against password hash stored in database. If valid
///             // return the user. HummingbirdAuth provides an implementation of Bcrypt
///             if Bcrypt.verify(basic.password, hash: user.passwordHash) {
///                 return user
///             }
///             return nil
///         }
///         // hop back to request eventloop
///         .hop(to: request.eventLoop)
///     }
/// }
/// ```
public protocol HBAuthenticator: HBMiddleware {
    /// type to be authenticated
    associatedtype Value: HBAuthenticatable
    /// Called by middleware to see if request is authenticated.
    ///
    /// Should return an authenticatable object if authenticated, return nil is not authenticated
    /// but want the request to be passed onto the next middleware or the router, or return a
    /// failed `EventLoopFuture` if the request should not proceed any further
    func authenticate(request: HBRequest) -> EventLoopFuture<Value?>
}

extension HBAuthenticator {
    /// Calls `authenticate` and if it returns a valid autheniticatable object `login` with this object
    public func apply(to request: HBRequest, next: HBResponder) -> EventLoopFuture<HBResponse> {
        authenticate(request: request)
            .flatMap { authenticated in
                var request = request
                if let authenticated = authenticated {
                    request.authLogin(authenticated)
                }
                return next.respond(to: request)
            }
    }
}
