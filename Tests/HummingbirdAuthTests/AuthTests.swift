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
import HummingbirdAuthTesting
import HummingbirdTesting
import NIOPosix
import XCTest

final class AuthTests: XCTestCase {
    func testBcrypt() {
        let hash = Bcrypt.hash("password")
        XCTAssert(Bcrypt.verify("password", hash: hash))
    }

    func testBcryptFalse() {
        let hash = Bcrypt.hash("password")
        XCTAssertFalse(Bcrypt.verify("password1", hash: hash))
    }

    func testMultipleBcrypt() async throws {
        struct VerifyFailError: Error {}

        try await withThrowingTaskGroup(of: Void.self) { group in
            for i in 0..<8 {
                group.addTask {
                    let text = "This is a test \(i)"
                    let hash = Bcrypt.hash(text)
                    if Bcrypt.verify(text, hash: hash) {
                        return
                    } else {
                        throw VerifyFailError()
                    }
                }
            }
            try await group.waitForAll()
        }
    }

    func testBearer() async throws {
        let router = Router(context: BasicAuthRequestContext.self)
        router.get { request, _ -> String? in
            return request.headers.bearer?.token
        }
        let app = Application(responder: router.buildResponder())
        try await app.test(.router) { client in
            try await client.execute(uri: "/", method: .get, auth: .bearer("1234567890")) { response in
                let body = try XCTUnwrap(response.body)
                XCTAssertEqual(String(buffer: body), "1234567890")
            }
            try await client.execute(uri: "/", method: .get, auth: .basic(username: "adam", password: "1234")) { response in
                XCTAssertEqual(response.status, .noContent)
            }
        }
    }

    func testBasic() async throws {
        let router = Router(context: BasicAuthRequestContext.self)
        router.get { request, _ -> String? in
            return request.headers.basic.map { "\($0.username):\($0.password)" }
        }
        let app = Application(responder: router.buildResponder())
        try await app.test(.router) { client in
            try await client.execute(uri: "/", method: .get, auth: .basic(username: "adam", password: "password")) { response in
                let body = try XCTUnwrap(response.body)
                XCTAssertEqual(String(buffer: body), "adam:password")
            }
        }
    }

    func testBcryptThread() async throws {
        let persist = MemoryPersistDriver()
        let router = Router(context: BasicAuthRequestContext.self)
        router.put { request, _ -> HTTPResponse.Status in
            guard let basic = request.headers.basic else { throw HTTPError(.unauthorized) }
            let hash = try await NIOThreadPool.singleton.runIfActive {
                Bcrypt.hash(basic.password)
            }
            try await persist.set(key: basic.username, value: hash)
            return .ok
        }
        router.post { request, _ -> HTTPResponse.Status in
            guard let basic = request.headers.basic else { throw HTTPError(.unauthorized) }
            guard let hash = try await persist.get(key: basic.username, as: String.self) else { throw HTTPError(.unauthorized) }
            let verified = try await NIOThreadPool.singleton.runIfActive {
                Bcrypt.verify(basic.password, hash: hash)
            }
            if verified {
                return .ok
            } else {
                return .unauthorized
            }
        }
        let app = Application(responder: router.buildResponder())
        try await app.test(.router) { client in
            try await client.execute(uri: "/", method: .put, auth: .basic(username: "testuser", password: "testpassword123")) { response in
                XCTAssertEqual(response.status, .ok)
            }
            try await client.execute(uri: "/", method: .post, auth: .basic(username: "testuser", password: "testpassword123")) { response in
                XCTAssertEqual(response.status, .ok)
            }
        }
    }

    func testAuth() async throws {
        struct User: Authenticatable {
            let name: String
        }
        let router = Router(context: BasicAuthRequestContext.self)
        router.get { _, context -> HTTPResponse.Status in
            var context = context
            context.auth.login(User(name: "Test"))
            XCTAssert(context.auth.has(User.self))
            XCTAssertEqual(context.auth.get(User.self)?.name, "Test")
            context.auth.logout(User.self)
            XCTAssertFalse(context.auth.has(User.self))
            XCTAssertNil(context.auth.get(User.self))
            return .accepted
        }
        let app = Application(responder: router.buildResponder())

        try await app.test(.router) { client in
            try await client.execute(uri: "/", method: .get) { response in
                XCTAssertEqual(response.status, .accepted)
            }
        }
    }

    func testLogin() async throws {
        struct User: Authenticatable {
            let name: String
        }
        struct TestAuthenticator<Context: AuthRequestContext>: Authenticator {
            func authenticate(request: Request, context: Context) async throws -> User? {
                User(name: "Adam")
            }
        }
        let router = Router(context: BasicAuthRequestContext.self)
        router.middlewares.add(TestAuthenticator())
        router.get { _, context -> HTTPResponse.Status in
            guard context.auth.has(User.self) else { return .unauthorized }
            return .ok
        }
        let app = Application(responder: router.buildResponder())

        try await app.test(.router) { client in
            try await client.execute(uri: "/", method: .get) { response in
                XCTAssertEqual(response.status, .ok)
            }
        }
    }

    func testIsAuthenticatedMiddleware() async throws {
        struct User: Authenticatable {
            let name: String
        }
        struct TestAuthenticator<Context: AuthRequestContext>: Authenticator {
            func authenticate(request: Request, context: Context) async throws -> User? {
                User(name: "Adam")
            }
        }
        let router = Router(context: BasicAuthRequestContext.self)
        router.group()
            .add(middleware: TestAuthenticator())
            .add(middleware: IsAuthenticatedMiddleware(User.self))
            .get("authenticated") { _, _ -> HTTPResponse.Status in
                return .ok
            }
        router.group()
            .add(middleware: IsAuthenticatedMiddleware(User.self))
            .get("unauthenticated") { _, _ -> HTTPResponse.Status in
                return .ok
            }
        let app = Application(responder: router.buildResponder())

        try await app.test(.router) { client in
            try await client.execute(uri: "/authenticated", method: .get) { response in
                XCTAssertEqual(response.status, .ok)
            }
            try await client.execute(uri: "/unauthenticated", method: .get) { response in
                XCTAssertEqual(response.status, .unauthorized)
            }
        }
    }

    func testSessionAuthenticator() async throws {
        struct User: Authenticatable {
            let name: String
        }
        struct MySessionAuthenticator<Context: AuthRequestContext>: SessionAuthenticator {
            let sessionStorage: SessionStorage

            func getValue(from session: Int, request: Request, context: Context) async throws -> User? {
                return User(name: "Adam")
            }
        }
        let router = Router(context: BasicAuthRequestContext.self)
        let persist = MemoryPersistDriver()
        let sessions = SessionStorage(persist)

        router.put("session") { _, _ -> Response in
            let cookie = try await sessions.save(session: 1, expiresIn: .seconds(60))
            var response = Response(status: .ok)
            response.setCookie(cookie)
            return response
        }
        router.group()
            .add(middleware: MySessionAuthenticator(sessionStorage: sessions))
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
}
