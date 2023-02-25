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

        var responseCookies: String?
        try app.XCTExecute(uri: "/session", method: .PUT) { response in
            responseCookies = response.headers["Set-Cookie"].first
            XCTAssertEqual(response.status, .ok)
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

        var sessionHeader: String?
        try app.XCTExecute(uri: "/session", method: .PUT) { response in
            sessionHeader = response.headers["session_id"].first
            XCTAssertEqual(response.status, .ok)
        }
        let header = try XCTUnwrap(sessionHeader)
        try app.XCTExecute(uri: "/session", method: .GET, headers: ["session_id": header]) { response in
            XCTAssertEqual(response.status, .ok)
        }
    }

    #if compiler(>=5.5) && canImport(_Concurrency)
    @available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *)
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

        var responseCookies: String?
        try app.XCTExecute(uri: "/session", method: .PUT, auth: .basic(username: "adam", password: "password123")) { response in
            responseCookies = response.headers["Set-Cookie"].first
            XCTAssertEqual(response.status, .ok)
        }
        let cookies = try XCTUnwrap(responseCookies)
        try app.XCTExecute(uri: "/session", method: .GET, headers: ["Cookie": cookies]) { response in
            XCTAssertEqual(response.status, .ok)
            let buffer = try XCTUnwrap(response.body)
            XCTAssertEqual(String(buffer: buffer), "adam")
        }
    }

    @available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *)
    func testSessionUpdate() async throws {
        struct User: Codable {
            let name: String
        }

        let app = HBApplication(testing: .asyncTest)
        app.addSessions(using: .memory)
        app.router.post("save", options: .editResponse) { request in
            guard let name = request.uri.queryParameters.get("name") else { throw HBHTTPError(.badRequest) }
            try await request.session.save(session: User(name: name), expiresIn: .minutes(10))
            return HTTPResponseStatus.ok
        }
        app.router.post("update") { request in
            guard let name = request.uri.queryParameters.get("name") else { throw HBHTTPError(.badRequest) }
            try await request.session.update(session: User(name: name), expiresIn: .minutes(10))
            return HTTPResponseStatus.ok
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

    #endif // compiler(>=5.5) && canImport(_Concurrency)
}
