//===----------------------------------------------------------------------===//
//
// This source file is part of the Hummingbird server framework project
//
// Copyright (c) 2021-2024 the Hummingbird authors
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
import HummingbirdAuthTesting
import HummingbirdTesting
import NIOPosix
import XCTest

final class SessionTests: XCTestCase {
    func testSessionAuthenticator() async throws {
        struct TestUserRepository: UserRepository {
            struct User: Authenticatable {
                let name: String
            }

            typealias Identifier = Int

            static let testSessionId = 89

            func getUser(from id: Identifier, context: BasicAuthRequestContext) async throws -> User? {
                let user = self.users[id]
                return user
            }

            let users = [Self.testSessionId: User(name: "Adam")]
        }

        let router = Router(context: BasicAuthRequestContext.self)
        let persist = MemoryPersistDriver()
        let sessions = SessionStorage(persist)
        router.put("session") { _, _ -> Response in
            let cookie = try await sessions.save(session: TestUserRepository.testSessionId, expiresIn: .seconds(300))
            var response = Response(status: .ok)
            response.setCookie(cookie)
            return response
        }
        router.group()
            .add(middleware: SessionAuthenticator(users: TestUserRepository(), sessionStorage: sessions))
            .get("session") { _, context -> HTTPResponse.Status in
                _ = try context.auth.require(TestUserRepository.User.self)
                return .ok
            }
        let app = Application(responder: router.buildResponder())

        try await app.test(.router) { client in
            let responseCookies = try await client.execute(uri: "/session", method: .put) { response -> String? in
                XCTAssertEqual(response.status, .ok)
                return response.headers[.setCookie]
            }
            let cookies = try XCTUnwrap(responseCookies)
            try await client.execute(uri: "/session", method: .get, headers: [.cookie: cookies]) { response in
                XCTAssertEqual(response.status, .ok)
            }
        }
    }

    func testSessionAuthenticatorClosure() async throws {
        struct User: Authenticatable {
            let name: String
        }
        let router = Router(context: BasicAuthRequestContext.self)
        let persist = MemoryPersistDriver()
        let sessions = SessionStorage(persist)
        router.put("session") { _, _ -> Response in
            let cookie = try await sessions.save(session: 1, expiresIn: .seconds(300))
            var response = Response(status: .ok)
            response.setCookie(cookie)
            return response
        }
        router.group()
            .add(
                middleware: SessionAuthenticator(sessionStorage: sessions) { (_: Int, _) in
                    User(name: "Adam")
                }
            )
            .get("session") { _, context -> HTTPResponse.Status in
                _ = try context.auth.require(User.self)
                return .ok
            }
        let app = Application(responder: router.buildResponder())

        try await app.test(.router) { client in
            let responseCookies = try await client.execute(uri: "/session", method: .put) { response -> String? in
                XCTAssertEqual(response.status, .ok)
                return response.headers[.setCookie]
            }
            let cookies = try XCTUnwrap(responseCookies)
            try await client.execute(uri: "/session", method: .get, headers: [.cookie: cookies]) { response in
                XCTAssertEqual(response.status, .ok)
            }
        }
    }

    func testSessionUpdate() async throws {
        struct User: Codable {
            let name: String
        }

        let router = Router(context: BasicAuthRequestContext.self)
        let persist = MemoryPersistDriver()
        let sessions = SessionStorage(persist)
        router.post("save") { request, _ -> Response in
            guard let name = request.uri.queryParameters.get("name") else { throw HTTPError(.badRequest) }
            let cookie = try await sessions.save(session: User(name: name), expiresIn: .seconds(600))
            var response = Response(status: .ok)
            response.setCookie(cookie)
            return response
        }
        router.post("update") { request, _ -> HTTPResponse.Status in
            guard let name = request.uri.queryParameters.get("name") else { throw HTTPError(.badRequest) }
            try await sessions.update(session: User(name: name), expiresIn: .seconds(600), request: request)
            return .ok
        }
        router.get("name") { request, _ -> String in
            guard let user = try await sessions.load(as: User.self, request: request) else { throw HTTPError(.unauthorized) }
            return user.name
        }
        let app = Application(responder: router.buildResponder())

        try await app.test(.router) { client in
            let cookies = try await client.execute(uri: "/save?name=john", method: .post) { response -> String? in
                XCTAssertEqual(response.status, .ok)
                return response.headers[.setCookie]
            }
            try await client.execute(uri: "/update?name=jane", method: .post, headers: cookies.map { [.cookie: $0] } ?? [:]) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertNil(response.headers[.setCookie])
            }

            // get save username
            try await client.execute(uri: "/name", method: .get, headers: cookies.map { [.cookie: $0] } ?? [:]) { response in
                XCTAssertEqual(response.status, .ok)
                let buffer = try XCTUnwrap(response.body)
                XCTAssertEqual(String(buffer: buffer), "jane")
            }
        }
    }

    func testSessionUpdateError() async throws {
        let router = Router(context: BasicAuthRequestContext.self)
        let persist = MemoryPersistDriver()
        let sessions = SessionStorage(persist)

        router.post("update") { request, _ -> HTTPResponse.Status in
            do {
                try await sessions.update(session: "hello", expiresIn: .seconds(600), request: request)
                return .ok
            } catch {
                return .badRequest
            }
        }
        let app = Application(responder: router.buildResponder())

        try await app.test(.router) { client in
            try await client.execute(uri: "/update", method: .post) { response in
                XCTAssertEqual(response.status, .badRequest)
            }
        }
    }
}
