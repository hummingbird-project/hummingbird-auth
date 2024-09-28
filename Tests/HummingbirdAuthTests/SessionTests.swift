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
        struct TestUserRepository: UserSessionRepository {
            struct User: Authenticatable {
                let name: String
            }

            static let testSessionId = 89

            func getUser(from id: Int, context: UserRepositoryContext) async throws -> User? {
                let user = self.users[id]
                return user
            }

            let users = [Self.testSessionId: User(name: "Adam")]
        }

        let persist = MemoryPersistDriver()
        let sessions = SessionStorage(persist)

        let router = Router(context: BasicSessionRequestContext<Int>.self)
        router.addMiddleware {
            SessionMiddleware(sessionStorage: sessions)
        }
        router.put("session") { _, context -> Response in
            context.sessions.setSession(TestUserRepository.testSessionId)
            return .init(status: .ok)
        }
        router
            .authGroup(authenticator: SessionAuthenticator(users: TestUserRepository()))
            .get("session") { _, context -> HTTPResponse.Status in
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
        struct TestSession: Codable {
            let userID: String
        }
        let router = Router(context: BasicSessionRequestContext<TestSession>.self)
        let persist = MemoryPersistDriver()
        let sessions = SessionStorage(persist)
        router.addMiddleware {
            SessionMiddleware(sessionStorage: sessions)
        }
        router.put("session") { _, context -> HTTPResponse.Status in
            context.sessions.setSession(.init(userID: "Adam"))
            return .ok
        }
        router
            .authGroup(authenticator: SessionAuthenticator { session, _ in
                User(name: session.userID)
            })
            .get("session") { _, context -> HTTPResponse.Status in
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
            var name: String
        }

        let router = Router(context: BasicSessionRequestContext<User>.self)
        let persist = MemoryPersistDriver()
        router.add(middleware: SessionMiddleware(storage: persist))
        router.post("save") { request, context -> HTTPResponse.Status in
            guard let name = request.uri.queryParameters.get("name") else { throw HTTPError(.badRequest) }
            context.sessions.setSession(User(name: name), expiresIn: .seconds(600))
            return .ok
        }
        router.post("update") { request, context -> HTTPResponse.Status in
            guard let name = request.uri.queryParameters.get("name") else { throw HTTPError(.badRequest) }
            context.sessions.withLockedSession { session in
                session?.name = name
            }
            return .ok
        }
        router.get("name") { _, context -> String in
            guard let user = context.sessions.session else { throw HTTPError(.unauthorized) }
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

    func testSessionDeletion() async throws {
        struct User: Codable {
            let name: String
        }

        let router = Router(context: BasicSessionRequestContext<User>.self)
        let persist = MemoryPersistDriver()
        router.add(middleware: SessionMiddleware(storage: persist))
        router.post("login") { request, context -> HTTPResponse.Status in
            guard let name = request.uri.queryParameters.get("name") else { throw HTTPError(.badRequest) }
            context.sessions.setSession(User(name: name), expiresIn: .seconds(600))
            return .ok
        }
        router.post("logout") { _, context -> HTTPResponse.Status in
            context.sessions.clearSession()
            return .ok
        }
        router.get("name") { _, context -> String in
            guard let user = context.sessions.session else { throw HTTPError(.unauthorized) }
            return user.name
        }
        let app = Application(responder: router.buildResponder())

        try await app.test(.router) { client in
            let cookies = try await client.execute(uri: "/login?name=john", method: .post) { response -> String? in
                XCTAssertEqual(response.status, .ok)
                return response.headers[.setCookie]
            }
            // get username
            try await client.execute(uri: "/name", method: .get, headers: cookies.map { [.cookie: $0] } ?? [:]) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(String(buffer: response.body), "john")
            }
            let cookies2 = try await client.execute(uri: "/logout", method: .post) { response -> String? in
                XCTAssertEqual(response.status, .ok)
                return response.headers[.setCookie]
            }
            // get username
            try await client.execute(uri: "/name", method: .get, headers: cookies2.map { [.cookie: $0] } ?? [:]) { response in
                XCTAssertEqual(response.status, .unauthorized)
            }
        }
    }
}
