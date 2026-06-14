//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import AsyncHTTPClient
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import NIOCore
import NIOFoundationCompat

struct UserInfoClient: Sendable {
    let httpClient: HTTPClient

    func fetch(userInfoURL: String, accessToken: String) async throws -> OIDCClaims {
        var request = HTTPClientRequest(url: userInfoURL)
        request.method = .GET
        request.headers.add(name: "Authorization", value: "Bearer \(accessToken)")
        request.headers.add(name: "Accept", value: "application/json")

        let response = try await httpClient.execute(request, timeout: .seconds(10))
        guard response.status == .ok else {
            throw OIDCError.userInfoFailed(reason: "HTTP \(Int(response.status.code))")
        }
        let body = try await response.body.collect(upTo: 1024 * 256)
        return try JSONDecoder().decode(OIDCClaims.self, from: Data(buffer: body))
    }
}
