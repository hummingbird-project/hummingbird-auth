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
import Logging
import NIOCore
import NIOFoundationCompat

/// Performs the OAuth 2.0 / OIDC token endpoint exchange.
struct TokenExchange {
    let configuration: OIDCConfiguration
    let httpClient: HTTPClient
    let logger: Logger

    func exchange(
        code: String,
        pkceVerifier: String,
        tokenEndpointURL: String,
    ) async throws -> TokenResponse {
        var bodyPairs: [(String, String)] = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", configuration.redirectURI),
            ("code_verifier", pkceVerifier),
        ]
        var request = HTTPClientRequest(url: tokenEndpointURL)
        request.method = .POST
        request.headers.add(name: "Content-Type", value: "application/x-www-form-urlencoded")
        request.headers.add(name: "Accept", value: "application/json")
        try applyClientAuth(to: &request, bodyPairs: &bodyPairs)
        let bodyString = bodyPairs
            .map { key, value in "\(urlEncode(key))=\(urlEncode(value))" }
            .joined(separator: "&")
        request.body = .bytes(ByteBuffer(string: bodyString))
        return try await execute(request)
    }

    func refresh(
        refreshToken: String,
        tokenEndpointURL: String,
    ) async throws -> TokenResponse {
        var bodyPairs: [(String, String)] = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refreshToken),
            ("scope", configuration.scopes.joined(separator: " ")),
        ]
        var request = HTTPClientRequest(url: tokenEndpointURL)
        request.method = .POST
        request.headers.add(name: "Content-Type", value: "application/x-www-form-urlencoded")
        request.headers.add(name: "Accept", value: "application/json")
        try applyClientAuth(to: &request, bodyPairs: &bodyPairs)
        let bodyString = bodyPairs
            .map { key, value in "\(urlEncode(key))=\(urlEncode(value))" }
            .joined(separator: "&")
        request.body = .bytes(ByteBuffer(string: bodyString))
        return try await execute(request)
    }

    /// Applies the configured client authentication method to the request and body pairs.
    private func applyClientAuth(
        to request: inout HTTPClientRequest,
        bodyPairs: inout [(String, String)],
    ) throws {
        switch configuration.tokenEndpointAuthMethod {
        case .clientSecretBasic:
            guard let secret = configuration.clientSecret else {
                throw OIDCError.missingClientSecret
            }
            let encoded = Data("\(configuration.clientID):\(secret)".utf8).base64EncodedString()
            request.headers.add(name: "Authorization", value: "Basic \(encoded)")

        case .clientSecretPost:
            guard let secret = configuration.clientSecret else {
                throw OIDCError.missingClientSecret
            }
            bodyPairs.append(("client_id", configuration.clientID))
            bodyPairs.append(("client_secret", secret))

        case .none:
            bodyPairs.append(("client_id", configuration.clientID))
        }
    }

    private func execute(_ request: HTTPClientRequest) async throws -> TokenResponse {
        let response = try await httpClient.execute(request, timeout: .seconds(15))
        let responseBody = try await response.body.collect(upTo: 1024 * 256)
        let responseData = Data(buffer: responseBody)

        if response.status == .ok {
            let tokenResponse = try JSONDecoder().decode(TokenResponse.self, from: responseData)
            // OIDC Core §3.1.3.3: token_type MUST be "Bearer" (case-insensitive).
            guard let tokenType = tokenResponse.tokenType,
                  tokenType.caseInsensitiveCompare("Bearer") == .orderedSame
            else {
                throw OIDCError.providerError(
                    code: "invalid_token_type",
                    description: "Expected Bearer token_type, got \(tokenResponse.tokenType ?? "none")",
                )
            }
            // OIDC Core §3.1.3.3: server SHOULD return Cache-Control: no-store.
            let cacheControl = response.headers.first(name: "Cache-Control") ?? ""
            if !cacheControl.lowercased().contains("no-store") {
                logger.warning(
                    "Token endpoint response is missing Cache-Control: no-store",
                    metadata: ["url": "\(request.url)"],
                )
            }
            return tokenResponse
        } else {
            if let errorResponse = try? JSONDecoder().decode(TokenErrorResponse.self, from: responseData) {
                throw OIDCError.providerError(code: errorResponse.error, description: errorResponse.errorDescription)
            }
            let bodyStr = String(data: responseData, encoding: .utf8) ?? ""
            throw OIDCError.tokenExchangeFailed(statusCode: Int(response.status.code), body: bodyStr)
        }
    }

    func urlEncode(_ string: String) -> String {
        // RFC 3986 §2.3 unreserved characters — no Foundation needed, works on all platforms.
        string.utf8.reduce(into: "") { result, byte in
            switch byte {
            case UInt8(ascii: "A") ... UInt8(ascii: "Z"),
                 UInt8(ascii: "a") ... UInt8(ascii: "z"),
                 UInt8(ascii: "0") ... UInt8(ascii: "9"),
                 UInt8(ascii: "-"), UInt8(ascii: "."),
                 UInt8(ascii: "_"), UInt8(ascii: "~"):
                result.append(Character(UnicodeScalar(byte)))
            default:
                result += "%" + (byte < 16 ? "0" : "") + String(byte, radix: 16, uppercase: true)
            }
        }
    }
}
