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

        let responseCookies = try app.XCTExecute(uri: "/session", method: .PUT) { response -> String? in
            XCTAssertEqual(response.status, .ok)
            return response.headers["Set-Cookie"].first
        }
        let cookies = try XCTUnwrap(responseCookies)
        try app.XCTExecute(uri: "/session", method: .GET, headers: ["Cookie": cookies]) { response in
            XCTAssertEqual(response.status, .ok)
        }
    }

    func testSessionStoredInHeader() throws {
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
        app.addSessions(using: .memory, sessionID: .header("session_id"))

        try app.XCTStart()
        defer { app.XCTStop() }

        let sessionHeader = try app.XCTExecute(uri: "/session", method: .PUT) { response -> String? in
            XCTAssertEqual(response.status, .ok)
            return response.headers["session_id"].first
        }
        let header = try XCTUnwrap(sessionHeader)
        try app.XCTExecute(uri: "/session", method: .GET, headers: ["session_id": header]) { response in
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
        let app = HBApplication(testing: .asyncTest)
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

        let responseCookies = try app.XCTExecute(
            uri: "/session",
            method: .PUT,
            auth: .basic(username: "adam", password: "password123")
        ) { response -> String? in
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

    func testSessionUpdate() async throws {
        struct User: Codable {
            let name: String
        }

        let app = HBApplication(testing: .asyncTest)
        app.addSessions(using: .memory)
        app.router.post("save", options: .editResponse) { request -> HTTPResponseStatus in
            guard let name = request.uri.queryParameters.get("name") else { throw HBHTTPError(.badRequest) }
            try await request.session.save(session: User(name: name), expiresIn: .minutes(10))
            return .ok
        }
        app.router.post("update") { request -> HTTPResponseStatus in
            guard let name = request.uri.queryParameters.get("name") else { throw HBHTTPError(.badRequest) }
            try await request.session.update(session: User(name: name), expiresIn: .minutes(10))
            return .ok
        }
        app.router.get("name") { request -> String in
            guard let user = try await request.session.load(as: User.self) else { throw HBHTTPError(.unauthorized) }
            return user.name
        }

        try app.XCTStart()
        defer { app.XCTStop() }

        let cookies = try app.XCTExecute(uri: "/save?name=john", method: .POST) { response -> String? in
            XCTAssertEqual(response.status, .ok)
            return response.headers["Set-Cookie"].first
        }
        try app.XCTExecute(uri: "/update?name=jane", method: .POST, headers: cookies.map { ["Cookie": $0] } ?? [:]) { response in
            XCTAssertEqual(response.status, .ok)
            XCTAssertNil(response.headers["Set-Cookie"].first)
        }

        // get save username
        try app.XCTExecute(uri: "/name", method: .GET, headers: cookies.map { ["Cookie": $0] } ?? [:]) { response in
            XCTAssertEqual(response.status, .ok)
            let buffer = try XCTUnwrap(response.body)
            XCTAssertEqual(String(buffer: buffer), "jane")
        }
    }

    func testSessionUpdateError() async throws {
        let app = HBApplication(testing: .asyncTest)
        app.addSessions(using: .memory)
        app.router.post("update", options: .editResponse) { request -> HTTPResponseStatus in
            do {
                try await request.session.update(session: "hello", expiresIn: .minutes(10))
                return .ok
            } catch {
                return .badRequest
            }
        }
        try app.XCTStart()
        defer { app.XCTStop() }

        try app.XCTExecute(uri: "/update", method: .POST) { response in
            XCTAssertEqual(response.status, .badRequest)
        }
    }

    func testSessionStorageOutsideApp() throws {
        struct User: HBAuthenticatable {
            let name: String
        }
        struct MySessionAuthenticator: HBSessionAuthenticator {
            let storage: HBSessionStorage
            init(storage: HBSessionStorage) {
                self.storage = storage
            }

            func getValue(from session: Int, request: HBRequest) -> EventLoopFuture<User?> {
                return request.success(.init(name: "Adam"))
            }

            func getSession(request: HBRequest) -> EventLoopFuture<Int?> {
                self.storage.load(request: request)
            }
        }
        let app = HBApplication(testing: .asyncTest)
        let persist = HBMemoryPersistDriver(eventLoopGroup: app.eventLoopGroup)
        let sessionStorage = HBSessionStorage(persist)
        app.router.put("session", options: .editResponse) { request -> HTTPResponseStatus in
            try await sessionStorage.save(session: 1, expiresIn: .minutes(5), request: request)
            return .ok
        }
        app.router.group()
            .add(middleware: MySessionAuthenticator(storage: sessionStorage))
            .get("session") { request -> HTTPResponseStatus in
                _ = try request.authRequire(User.self)
                return .ok
            }

        try app.XCTStart()
        defer { app.XCTStop() }

        let responseCookies = try app.XCTExecute(uri: "/session", method: .PUT) { response -> String? in
            XCTAssertEqual(response.status, .ok)
            return response.headers["Set-Cookie"].first
        }
        let cookies = try XCTUnwrap(responseCookies)
        try app.XCTExecute(uri: "/session", method: .GET, headers: ["Cookie": cookies]) { response in
            XCTAssertEqual(response.status, .ok)
        }
    }
}
