//===----------------------------------------------------------------------===//
//
// This source file is part of the Hummingbird server framework project
//
// Copyright (c) 2023 the Hummingbird authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See hummingbird/CONTRIBUTORS.txt for the list of Hummingbird authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Hummingbird

public struct LoginCache: Sendable {
    public init() {
        self.cache = [:]
    }

    /// Login with authenticatable object. Add object to cache
    /// - Parameter auth: authentication details
    public mutating func login<Auth: Authenticatable>(_ auth: Auth) {
        self.cache = [ObjectIdentifier(Auth.self): auth]
    }

    /// Logout authenticatable object. Removes object from cache
    /// - Parameter auth: authentication type
    public mutating func logout<Auth: Authenticatable>(_: Auth.Type) {
        self.cache[ObjectIdentifier(Auth.self)] = nil
    }

    /// Return authenticated type
    /// - Parameter auth: Type required
    public func get<Auth: Authenticatable>(_: Auth.Type) -> Auth? {
        return self.cache[ObjectIdentifier(Auth.self)] as? Auth
    }

    /// Require authenticated type
    /// - Parameter auth: Type required
    public func require<Auth: Authenticatable>(_: Auth.Type) throws -> Auth {
        guard let auth = get(Auth.self) else {
            throw HTTPError(.unauthorized)
        }
        return auth
    }

    /// Return if cache is authenticated with type
    /// - Parameter auth: Authentication type
    public func has<Auth: Authenticatable>(_: Auth.Type) -> Bool {
        return self.cache[ObjectIdentifier(Auth.self)] != nil
    }

    var cache: [ObjectIdentifier: Authenticatable]
}
