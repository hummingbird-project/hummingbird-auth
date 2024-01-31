//===----------------------------------------------------------------------===//
//
// This source file is part of the Hummingbird server framework project
//
// Copyright (c) 2021-2022 the Hummingbird authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See hummingbird/CONTRIBUTORS.txt for the list of Hummingbird authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Hummingbird
import HummingbirdAuth
import HummingbirdAuthXCT
import HummingbirdXCT
import NIOPosix
import XCTest

final class SessionTests: XCTestCase {
    func testSessionAuthenticator() async throws {
        struct User: HBAuthenticatable {
            let name: String
        }
        struct MySessionAuthenticator<Context: HBAuthRequestContext>: HBSessionAuthenticator {
            let sessionStorage: HBSessionStorage
            func getValue(from session: Int, request: HBRequest, context: Context) async throws -> User? {
                return User(name: "Adam")
            }
        }
        let router = HBRouter(context: HBBasicAuthRequestContext.self)
        let persist = HBMemoryPersistDriver()
        let sessions = HBSessionStorage(persist)
        router.put("session") { _, _ -> HBResponse in
            let cookie = try await sessions.save(session: 1, expiresIn: .seconds(300))
            var response = HBResponse(status: .ok)
            response.setCookie(cookie)
            return response
        }
        router.group()
            .add(middleware: MySessionAuthenticator(sessionStorage: sessions))
            .get("session") { _, context -> HTTPResponse.Status in
                _ = try context.auth.require(User.self)
                return .ok
            }
        let app = HBApplication(responder: router.buildResponder())

        try await app.test(.router) { client in
            let responseCookies = try await client.XCTExecute(uri: "/session", method: .put) { response -> String? in
                XCTAssertEqual(response.status, .ok)
                return response.headers[.setCookie]
            }
            let cookies = try XCTUnwrap(responseCookies)
            try await client.XCTExecute(uri: "/session", method: .get, headers: [.cookie: cookies]) { response in
                XCTAssertEqual(response.status, .ok)
            }
        }
    }

    func testSessionUpdate() async throws {
        struct User: Codable {
            let name: String
        }

        let router = HBRouter(context: HBBasicAuthRequestContext.self)
        let persist = HBMemoryPersistDriver()
        let sessions = HBSessionStorage(persist)
        router.post("save") { request, _ -> HBResponse in
            guard let name = request.uri.queryParameters.get("name") else { throw HBHTTPError(.badRequest) }
            let cookie = try await sessions.save(session: User(name: name), expiresIn: .seconds(600))
            var response = HBResponse(status: .ok)
            response.setCookie(cookie)
            return response
        }
        router.post("update") { request, _ -> HTTPResponse.Status in
            guard let name = request.uri.queryParameters.get("name") else { throw HBHTTPError(.badRequest) }
            try await sessions.update(session: User(name: name), expiresIn: .seconds(600), request: request)
            return .ok
        }
        router.get("name") { request, _ -> String in
            guard let user = try await sessions.load(as: User.self, request: request) else { throw HBHTTPError(.unauthorized) }
            return user.name
        }
        let app = HBApplication(responder: router.buildResponder())

        try await app.test(.router) { client in
            let cookies = try await client.XCTExecute(uri: "/save?name=john", method: .post) { response -> String? in
                XCTAssertEqual(response.status, .ok)
                return response.headers[.setCookie]
            }
            try await client.XCTExecute(uri: "/update?name=jane", method: .post, headers: cookies.map { [.cookie: $0] } ?? [:]) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertNil(response.headers[.setCookie])
            }

            // get save username
            try await client.XCTExecute(uri: "/name", method: .get, headers: cookies.map { [.cookie: $0] } ?? [:]) { response in
                XCTAssertEqual(response.status, .ok)
                let buffer = try XCTUnwrap(response.body)
                XCTAssertEqual(String(buffer: buffer), "jane")
            }
        }
    }

    func testSessionUpdateError() async throws {
        let router = HBRouter(context: HBBasicAuthRequestContext.self)
        let persist = HBMemoryPersistDriver()
        let sessions = HBSessionStorage(persist)

        router.post("update") { request, _ -> HTTPResponse.Status in
            do {
                try await sessions.update(session: "hello", expiresIn: .seconds(600), request: request)
                return .ok
            } catch {
                return .badRequest
            }
        }
        let app = HBApplication(responder: router.buildResponder())

        try await app.test(.router) { client in
            try await client.XCTExecute(uri: "/update", method: .post) { response in
                XCTAssertEqual(response.status, .badRequest)
            }
        }
    }
}
