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

    func testMultipleBcrypt() throws {
        struct VerifyFailError: Error {}
        let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 8)
        let futures: [EventLoopFuture<Void>] = (0..<8).map { number in
            eventLoopGroup.next().submit {
                let text = "This is a test \(number)"
                let hash = Bcrypt.hash(text)
                if Bcrypt.verify(text, hash: hash) {
                    return
                } else {
                    throw VerifyFailError()
                }
            }
        }
        _ = try EventLoopFuture.whenAllSucceed(futures, on: eventLoopGroup.next()).wait()
    }

    func testBearer() async throws {
        let app = HBApplicationBuilder()
        app.router.get { request -> String? in
            return request.authBearer?.token
        }
        try await app.buildAndTest(.router) { client in
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
        let app = HBApplicationBuilder()
        app.router.get { request -> String? in
            return request.authBasic.map { "\($0.username):\($0.password)" }
        }
        try await app.buildAndTest(.router) { client in
            try await client.XCTExecute(uri: "/", method: .GET, auth: .basic(username: "adam", password: "password")) { response in
                let body = try XCTUnwrap(response.body)
                XCTAssertEqual(String(buffer: body), "adam:password")
            }
        }
    }

    func testBcryptThread() async throws {
        let app = HBApplicationBuilder()
        let persist = HBMemoryPersistDriver(eventLoopGroup: app.eventLoopGroup)
        app.router.put { request -> EventLoopFuture<HTTPResponseStatus> in
            guard let basic = request.authBasic else { return request.failure(.unauthorized) }
            return Bcrypt.hash(basic.password, for: request).flatMap { hash -> EventLoopFuture<Void> in
                persist.set(key: basic.username, value: hash, expires: nil, request: request)
            }.map {
                HTTPResponseStatus.ok
            }
        }
        app.router.post { request -> EventLoopFuture<HTTPResponseStatus> in
            guard let basic = request.authBasic else { return request.failure(.unauthorized) }
            return persist.get(key: basic.username, as: String.self, request: request).flatMap { hash in
                guard let hash = hash else { return request.failure(.unauthorized) }
                return Bcrypt.verify(basic.password, hash: hash, for: request)
            }.map { (result: Bool) in
                if result {
                    return .ok
                } else {
                    return .unauthorized
                }
            }
        }
        try await app.buildAndTest(.router) { client in
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
        let app = HBApplicationBuilder()
        app.router.get { request -> HTTPResponseStatus in
            var request = request
            request.authLogin(User(name: "Test"))
            XCTAssert(request.authHas(User.self))
            XCTAssertEqual(request.authGet(User.self)?.name, "Test")
            request.authLogout(User.self)
            XCTAssertFalse(request.authHas(User.self))
            XCTAssertNil(request.authGet(User.self))
            return .accepted
        }

        try await app.buildAndTest(.router) { client in
            try await client.XCTExecute(uri: "/", method: .GET) { response in
                XCTAssertEqual(response.status, .accepted)
            }
        }
    }

    func testLogin() async throws {
        struct User: HBAuthenticatable {
            let name: String
        }
        struct HBTestAuthenticator: HBAuthenticator {
            func authenticate(request: HBRequest) -> EventLoopFuture<User?> {
                return request.success(User(name: "Adam"))
            }
        }

        let app = HBApplicationBuilder()
        app.middleware.add(HBTestAuthenticator())
        app.router.get { request -> HTTPResponseStatus in
            guard request.authHas(User.self) else { return .unauthorized }
            return .ok
        }

        try await app.buildAndTest(.router) { client in
            try await client.XCTExecute(uri: "/", method: .GET) { response in
                XCTAssertEqual(response.status, .ok)
            }
        }
    }

    func testIsAuthenticatedMiddleware() async throws {
        struct User: HBAuthenticatable {
            let name: String
        }
        struct HBTestAuthenticator: HBAuthenticator {
            func authenticate(request: HBRequest) -> EventLoopFuture<User?> {
                return request.success(User(name: "Adam"))
            }
        }

        let app = HBApplicationBuilder()
        app.router.group()
            .add(middleware: HBTestAuthenticator())
            .add(middleware: IsAuthenticatedMiddleware(User.self))
            .get("authenticated") { _ -> HTTPResponseStatus in
                return .ok
            }
        app.router.group()
            .add(middleware: IsAuthenticatedMiddleware(User.self))
            .get("unauthenticated") { _ -> HTTPResponseStatus in
                return .ok
            }

        try await app.buildAndTest(.router) { client in
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
        struct MySessionAuthenticator: HBSessionAuthenticator {
            let sessionStorage: HBSessionStorage

            func getValue(from session: Int, request: HBRequest) -> EventLoopFuture<User?> {
                return request.success(.init(name: "Adam"))
            }
        }
        let app = HBApplicationBuilder()
        let persist = HBMemoryPersistDriver(eventLoopGroup: app.eventLoopGroup)
        let sessions = HBSessionStorage(persist)

        app.router.put("session", options: .editResponse) { request -> EventLoopFuture<HTTPResponseStatus> in
            return sessions.save(session: 1, expiresIn: .minutes(5), request: request).map { _ in .ok }
        }
        app.router.group()
            .add(middleware: MySessionAuthenticator(sessionStorage: sessions))
            .get("session") { request -> HTTPResponseStatus in
                _ = try request.authRequire(User.self)
                return .ok
            }

        try await app.buildAndTest(.router) { client in
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

    func testAsyncAuthenticator() async throws {
        struct User: HBAuthenticatable {
            let name: String
        }
        struct HBTestAuthenticator: HBAsyncAuthenticator {
            func authenticate(request: HBRequest) async throws -> User? {
                return .init(name: "Adam")
            }
        }

        let app = HBApplicationBuilder()
        app.middleware.add(HBTestAuthenticator())
        app.router.get { request -> HTTPResponseStatus in
            guard request.authHas(User.self) else { return .unauthorized }
            return .ok
        }

        try await app.buildAndTest(.router) { client in
            try await client.XCTExecute(uri: "/", method: .GET) { response in
                XCTAssertEqual(response.status, .ok)
            }
        }
    }

    func testAsyncSessionAuthenticator() async throws {
        struct User: HBAuthenticatable {
            let name: String
        }
        struct MySessionAuthenticator: HBAsyncSessionAuthenticator {
            typealias Session = UUID
            typealias Value = User

            let sessionStorage: HBSessionStorage
            let persist: HBMemoryPersistDriver

            func getValue(from session: UUID, request: HBRequest) async throws -> User? {
                let name = try await persist.get(key: session.uuidString, as: String.self, request: request)
                return name.map { .init(name: $0) }
            }
        }
        let app = HBApplicationBuilder()
        let persist = HBMemoryPersistDriver(eventLoopGroup: app.eventLoopGroup)
        let sessions = HBSessionStorage(persist)

        app.router.put("session", options: .editResponse) { request -> HTTPResponseStatus in
            guard let basic = request.authBasic else { throw HBHTTPError(.unauthorized) }
            let session = UUID()
            try await persist.create(key: session.uuidString, value: basic.username, request: request)
            try await sessions.save(session: session, expiresIn: .minutes(5), request: request)
            return .ok
        }
        app.router.group()
            .add(middleware: MySessionAuthenticator(sessionStorage: sessions, persist: persist))
            .get("session") { request -> String in
                let user = try request.authRequire(User.self)
                return user.name
            }

        try await app.buildAndTest(.router) { client in
            let responseCookies = try await client.XCTExecute(
                uri: "/session",
                method: .PUT,
                auth: .basic(username: "adam", password: "password123")
            ) { response -> String? in
                XCTAssertEqual(response.status, .ok)
                return response.headers["Set-Cookie"].first
            }
            let cookies = try XCTUnwrap(responseCookies)
            try await client.XCTExecute(uri: "/session", method: .GET, headers: ["Cookie": cookies]) { response in
                XCTAssertEqual(response.status, .ok)
                let buffer = try XCTUnwrap(response.body)
                XCTAssertEqual(String(buffer: buffer), "adam")
            }
        }
    }
}
