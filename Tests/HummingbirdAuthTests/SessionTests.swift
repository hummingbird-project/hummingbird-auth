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

import Foundation
import HummingbirdAuth
import HummingbirdAuthTesting
import HummingbirdTesting
import NIOPosix
import Testing

@testable import Hummingbird

struct SessionTests {
    @Test func testSessionAuthenticator() async throws {
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
                #expect(response.status == .ok)
                return response.headers[.setCookie]
            }
            let cookies = try #require(responseCookies)
            try await client.execute(uri: "/session", method: .get, headers: [.cookie: cookies]) { response in
                #expect(response.status == .ok)
            }
        }
    }

    @Test func testSessionAuthenticatorClosure() async throws {
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
                    User(name: session.userID)
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
                #expect(response.status == .ok)
                return response.headers[.setCookie]
            }
            let cookies = try #require(responseCookies)
            try await client.execute(uri: "/session", method: .get, headers: [.cookie: cookies]) { response in
                #expect(response.status == .ok)
            }
        }
    }

    @Test func testSessionUpdate() async throws {
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
            var cookie = try await client.execute(uri: "/save?name=john", method: .post) { response -> String in
                #expect(response.status == .ok)
                return try #require(response.headers[.setCookie])
            }
            try await client.execute(uri: "/update?name=jane", method: .post, headers: [.cookie: cookie]) { response in
                #expect(response.status == .ok)
                #expect(response.headers[.setCookie] == nil)
            }
            // get save username
            try await client.execute(uri: "/name", method: .get, headers: [.cookie: cookie]) { response in
                #expect(response.status == .ok)
                let buffer = response.body
                #expect(String(buffer: buffer) == "jane")
            }
            cookie = try await client.execute(uri: "/updateExpires?name=joan", method: .post, headers: [.cookie: cookie]) { response in
                #expect(response.status == .ok)
                // if we update the cookie expiration date a set-cookie header should be returned
                let newCookieHeader = try #require(response.headers[.setCookie])
                // check we are updating the existing cookie
                let cookieCookie = try #require(Cookie(from: cookie[...]))
                let newCookie = try #require(Cookie(from: newCookieHeader[...]))
                #expect(cookieCookie.value == newCookie.value)
                return newCookieHeader
            }
            // get save username
            try await client.execute(uri: "/name", method: .get, headers: [.cookie: cookie]) { response in
                #expect(response.status == .ok)
                let body = response.body
                #expect(String(buffer: body) == "joan")
            }
        }
    }

    @Test func testSessionDeletion() async throws {
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
                #expect(response.status == .ok)
                return response.headers[.setCookie]
            }
            // get username
            try await client.execute(uri: "/name", method: .get, headers: cookies.map { [.cookie: $0] } ?? [:]) { response in
                #expect(response.status == .ok)
                #expect(String(buffer: response.body) == "john")
            }
            let cookies2 = try await client.execute(uri: "/logout", method: .post) { response -> String? in
                #expect(response.status == .ok)
                return response.headers[.setCookie]
            }
            // get username
            try await client.execute(uri: "/name", method: .get, headers: cookies2.map { [.cookie: $0] } ?? [:]) { response in
                #expect(response.status == .unauthorized)
            }
        }
    }

    @Test func testSessionCookieParameters() async throws {
        struct User: Codable, Sendable {
            var name: String
        }

        let router = Router(context: BasicSessionRequestContext<User, User>.self)
        let persist = MemoryPersistDriver()
        router.add(
            middleware: SessionMiddleware(
                storage: persist,
                configuration: .init(
                    sessionCookieParameters: .init(
                        name: "TEST_SESSION_COOKIE",
                        domain: "https://test.com",
                        path: "/test",
                        secure: true,
                        sameSite: .strict
                    )
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
                #expect(response.status == .ok)
                let setCookieHeader = try #require(response.headers[.setCookie])
                let cookie = try #require(Cookie(from: setCookieHeader[...]))
                #expect(cookie.name == "TEST_SESSION_COOKIE")
                #expect(cookie.domain == "https://test.com")
                #expect(cookie.path == "/test")
                #expect(cookie.secure == true)
                #expect(cookie.sameSite == .strict)
            }
        }
    }

    /// Save session as one type and retrieve as another.
    @Test func testInvalidSession() async throws {
        struct User: Codable, Sendable {
            let name: String
        }

        let router = Router(context: BasicSessionRequestContext<UUID, User>.self)
        let persist = MemoryPersistDriver()
        let sessionStorage = SessionStorage<Int>(persist)
        let cookie = try await sessionStorage.save(session: 1, expiresIn: .seconds(60))
        router.add(middleware: SessionMiddleware(storage: persist))
        router.post("test") { _, context in
            context.sessions.session?.description
        }
        let app = Application(responder: router.buildResponder())

        try await app.test(.router) { client in
            try await client.execute(uri: "/test", method: .post, headers: [.cookie: cookie.description]) { response in
                #expect(response.status == .noContent)
                let setCookieHeader = try #require(response.headers[.setCookie])
                let cookie = Cookie(from: setCookieHeader[...])
                let expires = try #require(cookie?.expires)
                #expect(expires <= .now)
            }
        }
    }
}
