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

import Bcrypt
import Hummingbird
import HummingbirdAuth
import HummingbirdAuthTesting
import HummingbirdBasicAuth
import HummingbirdTesting
import NIOPosix
import XCTest

final class AuthTests: XCTestCase {
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
        struct Additional: Authenticatable {
            let something: String
        }
        let router = Router(context: BasicAuthRequestContext.self)
        router.get { _, context -> HTTPResponse.Status in
            var context = context
            context.auth.login(User(name: "Test"))
            context.auth.login(Additional(something: "abc"))

            XCTAssert(context.auth.has(User.self))
            XCTAssertEqual(context.auth.get(User.self)?.name, "Test")
            XCTAssert(context.auth.has(Additional.self))
            XCTAssertEqual(context.auth.get(Additional.self)?.something, "abc")

            context.auth.logout(User.self)
            XCTAssertFalse(context.auth.has(User.self))
            XCTAssertNil(context.auth.get(User.self))
            XCTAssert(context.auth.has(Additional.self))
            XCTAssertEqual(context.auth.get(Additional.self)?.something, "abc")

            context.auth.logout(Additional.self)
            XCTAssertFalse(context.auth.has(User.self))
            XCTAssertNil(context.auth.get(User.self))
            XCTAssertFalse(context.auth.has(Additional.self))
            XCTAssertNil(context.auth.get(Additional.self))

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
        struct TestAuthenticator<Context: AuthRequestContext>: AuthenticatorMiddleware {
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
        struct TestAuthenticator<Context: AuthRequestContext>: AuthenticatorMiddleware {
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

    func testBasicAuthenticator() async throws {
        struct MyUserRepository: PasswordUserRepository {
            struct User: BasicAuthenticatorUser {
                let username: String
                let passwordHash: String?
            }

            func getUser(named username: String) -> User? {
                return self.users[username].map { .init(username: username, passwordHash: $0) }
            }

            let users = ["admin": Bcrypt.hash("password", cost: 8)]
        }
        let router = Router(context: BasicAuthRequestContext.self)
        router.add(middleware: BasicAuthenticator(users: MyUserRepository()))
        router.get { _, context -> String? in
            let user = try context.auth.require(MyUserRepository.User.self)
            return user.username
        }
        let app = Application(responder: router.buildResponder())
        try await app.test(.router) { client in
            try await client.execute(uri: "/", method: .get, auth: .basic(username: "admin", password: "password")) { response in
                let body = try XCTUnwrap(response.body)
                XCTAssertEqual(String(buffer: body), "admin")
            }
            try await client.execute(uri: "/", method: .get, auth: .basic(username: "adam", password: "password")) { response in
                XCTAssertEqual(response.status, .unauthorized)
            }
        }
    }

    func testBasicAuthenticatorWithClosure() async throws {
        struct User: BasicAuthenticatorUser {
            let username: String
            let passwordHash: String?
        }
        let users = ["admin": Bcrypt.hash("password", cost: 8)]
        let router = Router(context: BasicAuthRequestContext.self)
        router.add(
            middleware: BasicAuthenticator { username in
                return users[username].map { User(username: username, passwordHash: $0) }
            }
        )
        router.get { _, context -> String? in
            let user = try context.auth.require(User.self)
            return user.username
        }
        let app = Application(responder: router.buildResponder())
        try await app.test(.router) { client in
            try await client.execute(uri: "/", method: .get, auth: .basic(username: "admin", password: "password")) { response in
                let body = try XCTUnwrap(response.body)
                XCTAssertEqual(String(buffer: body), "admin")
            }
            try await client.execute(uri: "/", method: .get, auth: .basic(username: "adam", password: "password")) { response in
                XCTAssertEqual(response.status, .unauthorized)
            }
        }
    }
}
