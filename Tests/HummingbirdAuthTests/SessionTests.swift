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

@testable import Hummingbird
import HummingbirdAuth
import HummingbirdAuthTesting
import HummingbirdTesting
import NIOPosix
import XCTest

final class SessionTests: XCTestCase {
    func testSessionAuthenticator() async throws {
        struct User: Sendable {
            let name: String
        }

        struct TestUserRepository: UserSessionRepository {
            static let testSessionId = 89

            func getUser(from id: Int, context: UserRepositoryContext) async throws -> User? {
                let user = self.users[id]
                return user
            }

            let users = [Self.testSessionId: User(name: "Adam")]
        }

        let persist = MemoryPersistDriver()

        let router = Router(context: BasicSessionRequestContext<Int, User>.self)
        router.addMiddleware {
            SessionMiddleware(storage: persist)
        }
        router.put("session") { _, context -> Response in
            context.sessions.setSession(TestUserRepository.testSessionId)
            return .init(status: .ok)
        }
        router.group()
            .add(middleware: SessionAuthenticator(users: TestUserRepository()))
            .get("session") { _, context -> HTTPResponse.Status in
                guard context.identity != nil else {
                    return .unauthorized
                }
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
        struct User: Sendable {
            let name: String
        }
        struct TestSession: Codable {
            let userID: String
        }
        let router = Router(context: BasicSessionRequestContext<TestSession, User>.self)
        let persist = MemoryPersistDriver()
        router.addMiddleware {
            SessionMiddleware(storage: persist)
        }
        router.put("session") { _, context -> HTTPResponse.Status in
            context.sessions.setSession(.init(userID: "Adam"))
            return .ok
        }
        router.group()
            .addMiddleware {
                SessionAuthenticator { session, _ -> User? in
                    return User(name: session.userID)
                }
            }
            .get("session") { _, context -> HTTPResponse.Status in
                guard context.identity != nil else {
                    return .unauthorized
                }
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
        struct User: Codable, Sendable {
            var name: String
        }

        let router = Router(context: BasicSessionRequestContext<User, User>.self)
        let persist = MemoryPersistDriver()
        router.add(middleware: SessionMiddleware(storage: persist))
        router.post("save") { request, context -> HTTPResponse.Status in
            guard
                let name = request.uri.queryParameters.get("name")
            else {
                throw HTTPError(.badRequest)
            }
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
        router.post("updateExpires") { request, context -> HTTPResponse.Status in
            guard let name = request.uri.queryParameters.get("name") else { throw HTTPError(.badRequest) }
            context.sessions.setSession(.init(name: name), expiresIn: .seconds(600))
            return .ok
        }
        router.get("name") { _, context -> String in
            guard let user = context.sessions.session else { throw HTTPError(.unauthorized) }
            return user.name
        }
        let app = Application(responder: router.buildResponder())

        try await app.test(.router) { client in
            var cookies = try await client.execute(uri: "/save?name=john", method: .post) { response -> String? in
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
            cookies = try await client.execute(uri: "/updateExpires?name=joan", method: .post, headers: cookies.map { [.cookie: $0] } ?? [:]) { response in
                XCTAssertEqual(response.status, .ok)
                return try XCTUnwrap(response.headers[.setCookie])
            }
            // get save username
            try await client.execute(uri: "/name", method: .get, headers: cookies.map { [.cookie: $0] } ?? [:]) { response in
                XCTAssertEqual(response.status, .ok)
                let buffer = try XCTUnwrap(response.body)
                XCTAssertEqual(String(buffer: buffer), "joan")
            }
        }
    }

    func testSessionDeletion() async throws {
        struct User: Codable, Sendable {
            let name: String
        }

        let router = Router(context: BasicSessionRequestContext<User, User>.self)
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

    func testSessionCookieParameters() async throws {
        struct User: Codable, Sendable {
            var name: String
        }

        let router = Router(context: BasicSessionRequestContext<User, User>.self)
        let persist = MemoryPersistDriver()
        router.add(
            middleware: SessionMiddleware(
                storage: persist,
                sessionCookieParameters: .init(
                    name: "TEST_SESSION_COOKIE",
                    domain: "https://test.com",
                    path: "/test",
                    secure: true,
                    sameSite: .strict
                )
            )
        )
        router.post("save") { request, context -> HTTPResponse.Status in
            guard
                let name = request.uri.queryParameters.get("name")
            else {
                throw HTTPError(.badRequest)
            }
            context.sessions.setSession(User(name: name), expiresIn: .seconds(600))
            return .ok
        }
        let app = Application(responder: router.buildResponder())

        try await app.test(.router) { client in
            try await client.execute(uri: "/save?name=john", method: .post) { response in
                XCTAssertEqual(response.status, .ok)
                let setCookieHeader = try XCTUnwrap(response.headers[.setCookie])
                let cookie = try XCTUnwrap(Cookie(from: setCookieHeader[...]))
                XCTAssertEqual(cookie.name, "TEST_SESSION_COOKIE")
                XCTAssertEqual(cookie.domain, "https://test.com")
                XCTAssertEqual(cookie.path, "/test")
                XCTAssertEqual(cookie.secure, true)
                XCTAssertEqual(cookie.sameSite, .strict)
            }
        }
    }

    /// Save session as one type and retrieve as another.
    func testInvalidSession() async throws {
        struct User: Codable, Sendable {
            let name: String
        }

        let router = Router(context: BasicSessionRequestContext<UUID, User>.self)
        let persist = MemoryPersistDriver()
        let sessionStorage = SessionStorage<Int>(persist)
        let cookie = try await sessionStorage.save(session: 1, expiresIn: .seconds(60))
        router.add(middleware: SessionMiddleware(storage: persist))
        router.post("test") { _, context in
            return context.sessions.session?.description
        }
        let app = Application(responder: router.buildResponder())

        try await app.test(.router) { client in
            try await client.execute(uri: "/test", method: .post, headers: [.cookie: cookie.description]) { response in
                XCTAssertEqual(response.status, .noContent)
                let setCookieHeader = try XCTUnwrap(response.headers[.setCookie])
                let cookie = Cookie(from: setCookieHeader[...])
                let expires = try XCTUnwrap(cookie?.expires)
                XCTAssertLessThanOrEqual(expires, .now)
            }
        }
    }
}
