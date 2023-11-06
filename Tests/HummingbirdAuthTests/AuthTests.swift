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
        let router = HBRouterBuilder(context: HBTestAuthRouterContext.self)
        router.get { request, _ -> String? in
            return request.authBearer?.token
        }
        let app = HBApplication(responder: router.buildResponder())
        try await app.test(.router) { client in
            try await client.XCTExecute(uri: "/", method: .GET, auth: .bearer("1234567890")) { response in
                let body = try XCTUnwrap(response.body)
                XCTAssertEqual(String(buffer: body), "1234567890")
            }
            try await client.XCTExecute(uri: "/", method: .GET, auth: .basic(username: "adam", password: "1234")) { response in
                XCTAssertEqual(response.status, .noContent)
            }
        }
    }

    func testBasic() async throws {
        let router = HBRouterBuilder(context: HBTestAuthRouterContext.self)
        router.get { request, _ -> String? in
            return request.authBasic.map { "\($0.username):\($0.password)" }
        }
        let app = HBApplication(responder: router.buildResponder())
        try await app.test(.router) { client in
            try await client.XCTExecute(uri: "/", method: .GET, auth: .basic(username: "adam", password: "password")) { response in
                let body = try XCTUnwrap(response.body)
                XCTAssertEqual(String(buffer: body), "adam:password")
            }
        }
    }

    func testBcryptThread() async throws {
        let persist = HBMemoryPersistDriver()
        let router = HBRouterBuilder(context: HBTestAuthRouterContext.self)
        router.put { request, context -> HTTPResponseStatus in
            guard let basic = request.authBasic else { throw HBHTTPError(.unauthorized) }
            let hash = try await context.applicationContext.threadPool.runIfActive {
                Bcrypt.hash(basic.password)
            }
            try await persist.set(key: basic.username, value: hash)
            return .ok
        }
        router.post { request, context -> HTTPResponseStatus in
            guard let basic = request.authBasic else { throw HBHTTPError(.unauthorized) }
            guard let hash = try await persist.get(key: basic.username, as: String.self) else { throw HBHTTPError(.unauthorized) }
            let verified = try await context.applicationContext.threadPool.runIfActive {
                Bcrypt.verify(basic.password, hash: hash)
            }
            if verified {
                return .ok
            } else {
                return .unauthorized
            }
        }
        let app = HBApplication(responder: router.buildResponder())
        try await app.test(.router) { client in
            try await client.XCTExecute(uri: "/", method: .PUT, auth: .basic(username: "testuser", password: "testpassword123")) { response in
                XCTAssertEqual(response.status, .ok)
            }
            try await client.XCTExecute(uri: "/", method: .POST, auth: .basic(username: "testuser", password: "testpassword123")) { response in
                XCTAssertEqual(response.status, .ok)
            }
        }
    }

    func testAuth() async throws {
        struct User: HBAuthenticatable {
            let name: String
        }
        let router = HBRouterBuilder(context: HBTestAuthRouterContext.self)
        router.get { _, context -> HTTPResponseStatus in
            var context = context
            context.auth.login(User(name: "Test"))
            XCTAssert(context.auth.has(User.self))
            XCTAssertEqual(context.auth.get(User.self)?.name, "Test")
            context.auth.logout(User.self)
            XCTAssertFalse(context.auth.has(User.self))
            XCTAssertNil(context.auth.get(User.self))
            return .accepted
        }
        let app = HBApplication(responder: router.buildResponder())

        try await app.test(.router) { client in
            try await client.XCTExecute(uri: "/", method: .GET) { response in
                XCTAssertEqual(response.status, .accepted)
            }
        }
    }

    func testLogin() async throws {
        struct User: HBAuthenticatable {
            let name: String
        }
        struct HBTestAuthenticator<Context: HBAuthRequestContextProtocol>: HBAuthenticator {
            func authenticate(request: HBRequest, context: Context) async throws -> User? {
                User(name: "Adam")
            }
        }
        let router = HBRouterBuilder(context: HBTestAuthRouterContext.self)
        router.middlewares.add(HBTestAuthenticator())
        router.get { _, context -> HTTPResponseStatus in
            guard context.auth.has(User.self) else { return .unauthorized }
            return .ok
        }
        let app = HBApplication(responder: router.buildResponder())

        try await app.test(.router) { client in
            try await client.XCTExecute(uri: "/", method: .GET) { response in
                XCTAssertEqual(response.status, .ok)
            }
        }
    }

    func testIsAuthenticatedMiddleware() async throws {
        struct User: HBAuthenticatable {
            let name: String
        }
        struct HBTestAuthenticator<Context: HBAuthRequestContextProtocol>: HBAuthenticator {
            func authenticate(request: HBRequest, context: Context) async throws -> User? {
                User(name: "Adam")
            }
        }
        let router = HBRouterBuilder(context: HBTestAuthRouterContext.self)
        router.group()
            .add(middleware: HBTestAuthenticator())
            .add(middleware: IsAuthenticatedMiddleware(User.self))
            .get("authenticated") { _, _ -> HTTPResponseStatus in
                return .ok
            }
        router.group()
            .add(middleware: IsAuthenticatedMiddleware(User.self))
            .get("unauthenticated") { _, _ -> HTTPResponseStatus in
                return .ok
            }
        let app = HBApplication(responder: router.buildResponder())

        try await app.test(.router) { client in
            try await client.XCTExecute(uri: "/authenticated", method: .GET) { response in
                XCTAssertEqual(response.status, .ok)
            }
            try await client.XCTExecute(uri: "/unauthenticated", method: .GET) { response in
                XCTAssertEqual(response.status, .unauthorized)
            }
        }
    }

    func testSessionAuthenticator() async throws {
        struct User: HBAuthenticatable {
            let name: String
        }
        struct MySessionAuthenticator<Context: HBAuthRequestContextProtocol>: HBSessionAuthenticator {
            let sessionStorage: HBSessionStorage

            func getValue(from session: Int, request: HBRequest, context: Context) async throws -> User? {
                return User(name: "Adam")
            }
        }
        let router = HBRouterBuilder(context: HBTestAuthRouterContext.self)
        let persist = HBMemoryPersistDriver()
        let sessions = HBSessionStorage(persist)

        router.put("session") { _, _ -> HBResponse in
            let cookie = try await sessions.save(session: 1, expiresIn: .seconds(60))
            var response = HBResponse(status: .ok)
            response.setCookie(cookie)
            return response
        }
        router.group()
            .add(middleware: MySessionAuthenticator(sessionStorage: sessions))
            .get("session") { _, context -> HTTPResponseStatus in
                _ = try context.auth.require(User.self)
                return .ok
            }
        let app = HBApplication(responder: router.buildResponder())

        try await app.test(.router) { client in
            let responseCookies = try await client.XCTExecute(uri: "/session", method: .PUT) { response -> String? in
                XCTAssertEqual(response.status, .ok)
                return response.headers["Set-Cookie"].first
            }
            let cookies = try XCTUnwrap(responseCookies)
            try await client.XCTExecute(uri: "/session", method: .GET, headers: ["Cookie": cookies]) { response in
                XCTAssertEqual(response.status, .ok)
            }
        }
    }
}
