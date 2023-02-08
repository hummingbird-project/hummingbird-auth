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

import ExtrasBase64
import Hummingbird

/// Basic authentication information extracted from request header "Authorization"
public struct BasicAuthentication {
    public let username: String
    public let password: String
}

extension HBRequest {
    /// Return Basic (username/password) authorization information from request
    public var authBasic: BasicAuthentication? {
        // check for authorization header
        guard let authorization = self.headers["Authorization"].first else { return nil }
        // check for basic prefix
        guard authorization.hasPrefix("Basic ") else { return nil }
        // extract base64 data
        let base64 = String(authorization.dropFirst("Basic ".count))
        // decode base64
        guard let data = try? base64.base64decoded() else { return nil }
        // create string from data
        let usernamePassword = String(decoding: data, as: Unicode.UTF8.self)
        // split string
        let split = usernamePassword.split(separator: ":", maxSplits: 1)
        // need two splits
        guard split.count == 2 else { return nil }
        return .init(username: String(split[0]), password: String(split[1]))
    }
}

#if compiler(>=5.6)
extension BasicAuthentication: Sendable {}
#endif
