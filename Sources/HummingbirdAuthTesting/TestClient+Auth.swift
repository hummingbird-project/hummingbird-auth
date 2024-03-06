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
import HummingbirdTesting
import XCTest

/// Used to generate various authentication types for Testing framework
public struct HBTestAuthentication: Equatable {
    /// create basic authentication test
    public static func basic(username: String, password: String) -> Self {
        return .init(value: .basic(username: username, password: password))
    }

    /// create bearer authentication test
    public static func bearer(_ token: String) -> Self {
        return .init(value: .bearer(token))
    }

    /// create cookie authentication test
    public static func cookie(name: String, value: String) -> Self {
        return .init(value: .cookie(name: name, value: value))
    }

    func apply(uri: String, method: HTTPRequest.Method, headers: HTTPFields, body: ByteBuffer?) -> (uri: String, method: HTTPRequest.Method, headers: HTTPFields, body: ByteBuffer?) {
        switch self.value {
        case .basic(let username, let password):
            var headers = headers
            let usernamePassword = "\(username):\(password)"
            let authorization = "Basic \(String(base64Encoding: usernamePassword.utf8))"
            headers[.authorization] = authorization
            return (uri: uri, method: method, headers: headers, body: body)

        case .bearer(let token):
            var headers = headers
            headers[.authorization] = "Bearer \(token)"
            return (uri: uri, method: method, headers: headers, body: body)

        case .cookie(let name, let value):
            var headers = headers
            let newCookie: String
            if let cookie = headers[.cookie] {
                newCookie = "\(name)=\(value); \(cookie)"
            } else {
                newCookie = "\(name)=\(value)"
            }
            headers[.cookie] = newCookie
            return (uri: uri, method: method, headers: headers, body: body)
        }
    }

    /// Internal type
    private enum Internal: Equatable {
        case basic(username: String, password: String)
        case bearer(String)
        case cookie(name: String, value: String)
    }

    private let value: Internal
}

extension HBTestClientProtocol {
    /// Send request with authentication and call test callback on the response returned
    ///
    /// - Parameters:
    ///   - uri: URI to test
    ///   - method: HTTP Method to test
    ///   - headers: Request headers
    ///   - auth: Authentication details
    ///   - body: Request body
    ///   - testCallback: Callback to test response
    /// - Returns: Result of callback
    public func execute<Return>(
        uri: String,
        method: HTTPRequest.Method,
        headers: HTTPFields = [:],
        auth: HBTestAuthentication,
        body: ByteBuffer? = nil,
        testCallback: @escaping (HBTestResponse) throws -> Return
    ) async throws -> Return {
        let request = auth.apply(uri: uri, method: method, headers: headers, body: body)
        return try await self.execute(
            uri: request.uri,
            method: request.method,
            headers: request.headers,
            body: request.body,
            testCallback: testCallback
        )
    }
}
