//===----------------------------------------------------------------------===//
//
// This source file is part of the Hummingbird server framework project
//
// Copyright (c) 2021-2021 the Hummingbird authors
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
    func randomBuffer(size: Int) -> [UInt8] {
        var data = [UInt8](repeating: 0, count: size)
        data = data.map { _ in UInt8.random(in: 0...255) }
        return data
    }

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

        app.XCTExecute(uri: "/", method: .GET, auth: .bearer("1234567890")) { response in
            let body = try XCTUnwrap(response.body)
            XCTAssertEqual(String(buffer: body), "1234567890")
        }
        app.XCTExecute(uri: "/", method: .GET, auth: .basic(username: "adam", password: "1234")) { response in
            XCTAssertEqual(response.status, .notFound)
        }
    }

    func testBasic() throws {
        let app = HBApplication(testing: .embedded)
        app.router.get { request -> String? in
            return request.authBasic.map { "\($0.username):\($0.password)" }
        }
        try app.XCTStart()
        defer { app.XCTStop() }

        app.XCTExecute(uri: "/", method: .GET, auth: .basic(username: "adam", password: "password")) { response in
            let body = try XCTUnwrap(response.body)
            XCTAssertEqual(String(buffer: body), "adam:password")
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

        app.XCTExecute(uri: "/", method: .GET) { response in
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

        app.XCTExecute(uri: "/", method: .GET) { response in
            XCTAssertEqual(response.status, .ok)
        }
    }

    func testBase32() {
        let data = [UInt8]("ABCDEFGHITJKLMNOPQRSTUVWXYZabcedefé".utf8)
        let base32 = String(base32Encoding: data)
        XCTAssertEqual(base32, "IFBEGRCFIZDUQSKUJJFUYTKOJ5IFCUSTKRKVMV2YLFNGCYTDMVSGKZWDVE")
    }

    func testBase32EncodeDecode() {
        let data = self.randomBuffer(size: Int.random(in: 4000...8000))
        let base32 = String(base32Encoding: data)
        let data2 = try! base32.base32decoded()
        XCTAssertEqual(data, data2)
    }
}
