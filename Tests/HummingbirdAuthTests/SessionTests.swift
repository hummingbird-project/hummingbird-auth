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

    func testSessionStoredInHeader() async throws {
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
        let sessions = HBSessionStorage(persist, sessionID: .header("session_id"))
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
            let sessionHeader = try await client.XCTExecute(uri: "/session", method: .PUT) { response -> String? in
                XCTAssertEqual(response.status, .ok)
                return response.headers["session_id"].first
            }
            let header = try XCTUnwrap(sessionHeader)
            try await client.XCTExecute(uri: "/session", method: .GET, headers: ["session_id": header]) { response in
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
            let persist: HBPersistDriver

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

    func testSessionUpdate() async throws {
        struct User: Codable {
            let name: String
        }

        let app = HBApplicationBuilder()
        let persist = HBMemoryPersistDriver(eventLoopGroup: app.eventLoopGroup)
        let sessions = HBSessionStorage(persist)

        app.router.post("save", options: .editResponse) { request -> HTTPResponseStatus in
            guard let name = request.uri.queryParameters.get("name") else { throw HBHTTPError(.badRequest) }
            try await sessions.save(session: User(name: name), expiresIn: .minutes(10), request: request)
            return .ok
        }
        app.router.post("update") { request -> HTTPResponseStatus in
            guard let name = request.uri.queryParameters.get("name") else { throw HBHTTPError(.badRequest) }
            try await sessions.update(session: User(name: name), expiresIn: .minutes(10), request: request)
            return .ok
        }
        app.router.get("name") { request -> String in
            guard let user = try await sessions.load(as: User.self, request: request) else { throw HBHTTPError(.unauthorized) }
            return user.name
        }

        try await app.buildAndTest(.router) { client in
            let cookies = try await client.XCTExecute(uri: "/save?name=john", method: .POST) { response -> String? in
                XCTAssertEqual(response.status, .ok)
                return response.headers["Set-Cookie"].first
            }
            try await client.XCTExecute(uri: "/update?name=jane", method: .POST, headers: cookies.map { ["Cookie": $0] } ?? [:]) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertNil(response.headers["Set-Cookie"].first)
            }

            // get save username
            try await client.XCTExecute(uri: "/name", method: .GET, headers: cookies.map { ["Cookie": $0] } ?? [:]) { response in
                XCTAssertEqual(response.status, .ok)
                let buffer = try XCTUnwrap(response.body)
                XCTAssertEqual(String(buffer: buffer), "jane")
            }
        }
    }

    func testSessionUpdateError() async throws {
        let app = HBApplicationBuilder()
        let persist = HBMemoryPersistDriver(eventLoopGroup: app.eventLoopGroup)
        let sessions = HBSessionStorage(persist)

        app.router.post("update", options: .editResponse) { request -> HTTPResponseStatus in
            do {
                try await sessions.update(session: "hello", expiresIn: .minutes(10), request: request)
                return .ok
            } catch {
                return .badRequest
            }
        }

        try await app.buildAndTest(.router) { client in
            try await client.XCTExecute(uri: "/update", method: .POST) { response in
                XCTAssertEqual(response.status, .badRequest)
            }
        }
    }
}
