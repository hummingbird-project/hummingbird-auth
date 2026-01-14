//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import HTTPTypes
import Hummingbird

/// Bearer authentication information extracted from request header "Authorization"
public struct BearerAuthentication: Sendable {
    public let token: String
}

extension HTTPFields {
    /// Return Bearer authorization information from request
    public var bearer: BearerAuthentication? {
        // check for authorization header
        guard let authorization = self[.authorization] else { return nil }
        // check for bearer prefix
        guard authorization.hasPrefix("Bearer ") else { return nil }
        // return token
        return .init(token: String(authorization.dropFirst("Bearer ".count)))
    }
}
