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

    func testBearer() throws {
        let app = HBApplication(testing: .embedded)
        app.router.get { request -> String? in
            return request.authBearer?.token
        }
        try app.XCTStart()
        defer { app.XCTStop() }

        try app.XCTExecute(uri: "/", method: .GET, auth: .bearer("1234567890")) { response in
            let body = try XCTUnwrap(response.body)
            XCTAssertEqual(String(buffer: body), "1234567890")
        }
        try app.XCTExecute(uri: "/", method: .GET, auth: .basic(username: "adam", password: "1234")) { response in
            XCTAssertEqual(response.status, .noContent)
        }
    }

    func testBasic() throws {
        let app = HBApplication(testing: .embedded)
        app.router.get { request -> String? in
            return request.authBasic.map { "\($0.username):\($0.password)" }
        }
        try app.XCTStart()
        defer { app.XCTStop() }

        try app.XCTExecute(uri: "/", method: .GET, auth: .basic(username: "adam", password: "password")) { response in
            let body = try XCTUnwrap(response.body)
            XCTAssertEqual(String(buffer: body), "adam:password")
        }
    }

    func testBcryptThread() throws {
        let app = HBApplication(testing: .live)
        app.addPersist(using: .memory)
        app.router.put { request -> EventLoopFuture<HTTPResponseStatus> in
            guard let basic = request.authBasic else { return request.failure(.unauthorized) }
            return Bcrypt.hash(basic.password, for: request).flatMap { hash in
                request.persist.set(key: basic.username, value: hash)
            }.map { _ in
                .ok
            }
        }
        app.router.post { request -> EventLoopFuture<HTTPResponseStatus> in
            guard let basic = request.authBasic else { return request.failure(.unauthorized) }
            return request.persist.get(key: basic.username, as: String.self).flatMap { hash in
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
        try app.XCTStart()
        defer { app.XCTStop() }

        try app.XCTExecute(uri: "/", method: .PUT, auth: .basic(username: "testuser", password: "testpassword123")) { response in
            XCTAssertEqual(response.status, .ok)
        }
        try app.XCTExecute(uri: "/", method: .POST, auth: .basic(username: "testuser", password: "testpassword123")) { response in
            XCTAssertEqual(response.status, .ok)
        }
    }

    func testAuth() throws {
        struct User: HBAuthenticatable {
            let name: String
        }
        let app = HBApplication(testing: .embedded)
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

        try app.XCTStart()
        defer { app.XCTStop() }

        try app.XCTExecute(uri: "/", method: .GET) { response in
            XCTAssertEqual(response.status, .accepted)
        }
    }

    func testLogin() throws {
        struct User: HBAuthenticatable {
            let name: String
        }
        struct HBTestAuthenticator: HBAuthenticator {
            func authenticate(request: HBRequest) -> EventLoopFuture<User?> {
                return request.success(User(name: "Adam"))
            }
        }

        let app = HBApplication(testing: .embedded)
        app.middleware.add(HBTestAuthenticator())
        app.router.get { request -> HTTPResponseStatus in
            guard request.authHas(User.self) else { return .unauthorized }
            return .ok
        }

        try app.XCTStart()
        defer { app.XCTStop() }

        try app.XCTExecute(uri: "/", method: .GET) { response in
            XCTAssertEqual(response.status, .ok)
        }
    }

    func testIsAuthenticatedMiddleware() throws {
        struct User: HBAuthenticatable {
            let name: String
        }
        struct HBTestAuthenticator: HBAuthenticator {
            func authenticate(request: HBRequest) -> EventLoopFuture<User?> {
                return request.success(User(name: "Adam"))
            }
        }

        let app = HBApplication(testing: .embedded)
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

        try app.XCTStart()
        defer { app.XCTStop() }

        try app.XCTExecute(uri: "/authenticated", method: .GET) { response in
            XCTAssertEqual(response.status, .ok)
        }
        try app.XCTExecute(uri: "/unauthenticated", method: .GET) { response in
            XCTAssertEqual(response.status, .unauthorized)
        }
    }

    func testSessionAuthenticator() throws {
        struct User: HBAuthenticatable {
            let name: String
        }
        struct MySessionAuthenticator: HBSessionAuthenticator {
            func getValue(from session: Int, request: HBRequest) -> EventLoopFuture<User?> {
                return request.success(.init(name: "Adam"))
            }
        }
        let app = HBApplication(testing: .embedded)
        app.router.put("session", options: .editResponse) { request -> EventLoopFuture<HTTPResponseStatus> in
            return request.session.save(session: 1, expiresIn: .minutes(5)).map { _ in .ok }
        }
        app.router.group()
            .add(middleware: MySessionAuthenticator())
            .get("session") { request -> HTTPResponseStatus in
                _ = try request.authRequire(User.self)
                return .ok
            }
        app.addSessions(using: .memory)

        try app.XCTStart()
        defer { app.XCTStop() }

        let responseCookies = try app.XCTExecute(uri: "/session", method: .PUT) { response in
            XCTAssertEqual(response.status, .ok)
            return response.headers["Set-Cookie"].first
        }
        let cookies = try XCTUnwrap(responseCookies)
        try app.XCTExecute(uri: "/session", method: .GET, headers: ["Cookie": cookies]) { response in
            XCTAssertEqual(response.status, .ok)
        }
    }

    #if compiler(>=5.5) && canImport(_Concurrency)
    @available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *)
    func testAsyncAuthenticator() throws {
        struct User: HBAuthenticatable {
            let name: String
        }
        struct HBTestAuthenticator: HBAsyncAuthenticator {
            func authenticate(request: HBRequest) async throws -> User? {
                return .init(name: "Adam")
            }
        }

        let app = HBApplication(testing: .live)
        app.middleware.add(HBTestAuthenticator())
        app.router.get { request -> HTTPResponseStatus in
            guard request.authHas(User.self) else { return .unauthorized }
            return .ok
        }

        try app.XCTStart()
        defer { app.XCTStop() }

        try app.XCTExecute(uri: "/", method: .GET) { response in
            XCTAssertEqual(response.status, .ok)
        }
    }

    func testAsyncSessionAuthenticator() throws {
        struct User: HBAuthenticatable {
            let name: String
        }
        struct MySessionAuthenticator: HBAsyncSessionAuthenticator {
            typealias Session = UUID
            typealias Value = User

            func getValue(from session: UUID, request: HBRequest) async throws -> User? {
                let name = try await request.persist.get(key: session.uuidString, as: String.self)
                return name.map { .init(name: $0) }
            }
        }
        let app = HBApplication(testing: .live)
        app.router.put("session", options: .editResponse) { request -> HTTPResponseStatus in
            guard let basic = request.authBasic else { throw HBHTTPError(.unauthorized) }
            let session = UUID()
            try await request.persist.create(key: session.uuidString, value: basic.username)
            try await request.session.save(session: session, expiresIn: .minutes(5))
            return .ok
        }
        app.router.group()
            .add(middleware: MySessionAuthenticator())
            .get("session") { request -> String in
                let user = try request.authRequire(User.self)
                return user.name
            }
        app.addPersist(using: .memory)
        app.addSessions()

        try app.XCTStart()
        defer { app.XCTStop() }

        let responseCookies = try app.XCTExecute(uri: "/session", method: .PUT, auth: .basic(username: "adam", password: "password123")) { response in
            XCTAssertEqual(response.status, .ok)
            return response.headers["Set-Cookie"].first
        }
        let cookies = try XCTUnwrap(responseCookies)
        try app.XCTExecute(uri: "/session", method: .GET, headers: ["Cookie": cookies]) { response in
            XCTAssertEqual(response.status, .ok)
            let buffer = try XCTUnwrap(response.body)
            XCTAssertEqual(String(buffer: buffer), "adam")
        }
    }
    #endif // compiler(>=5.5) && canImport(_Concurrency)
}
