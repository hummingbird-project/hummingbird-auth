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

extension HBRequest {
    /// Login with authenticatable object. Make object available to request via `Auth.get`
    /// - Parameter auth: authentication details
    public mutating func authLogin<Auth: HBAuthenticatable>(_ auth: Auth) {
        if var cache = self.loginCache {
            cache[ObjectIdentifier(Auth.self)] = auth
            self.loginCache = cache
        } else {
            self.loginCache = [ObjectIdentifier(Auth.self): auth]
        }
    }

    /// Logout authenticatable object. Removes object from request
    /// - Parameter auth: authentication type
    public mutating func authLogout<Auth: HBAuthenticatable>(_: Auth.Type) {
        if var cache = self.loginCache {
            cache[ObjectIdentifier(Auth.self)] = nil
            self.loginCache = cache
        }
    }

    /// Return authenticated type
    /// - Parameter auth: Type required
    public func authGet<Auth: HBAuthenticatable>(_: Auth.Type) -> Auth? {
        return self.loginCache?[ObjectIdentifier(Auth.self)] as? Auth
    }

    /// Return authenticated type
    /// - Parameter auth: Type required
    public func authRequire<Auth: HBAuthenticatable>(_: Auth.Type) throws -> Auth {
        guard let auth = self.loginCache?[ObjectIdentifier(Auth.self)] as? Auth else {
            throw HBHTTPError(.unauthorized)
        }
        return auth
    }

    /// Return if request is authenticated with type
    /// - Parameter auth: Authentication type
    public func authHas<Auth: HBAuthenticatable>(_: Auth.Type) -> Bool {
        return self.loginCache?[ObjectIdentifier(Auth.self)] != nil
    }

    /// cache of all the objects that have been logged in
    var loginCache: [ObjectIdentifier: HBAuthenticatable]? {
        get { self.extensions.get(\.loginCache) }
        set { self.extensions.set(\.loginCache, value: newValue) }
    }
}
