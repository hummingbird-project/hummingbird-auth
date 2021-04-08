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
import HummingbirdXCT
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

    func testBearer() {
        let app = HBApplication(testing: .embedded)
        app.router.get { request -> String? in
            return request.auth.bearer?.token
        }
        app.XCTStart()
        defer { app.XCTStop() }

        app.XCTExecute(uri: "/", method: .GET, headers: ["Authorization": "Bearer 1234567890"]) { response in
            let body = try XCTUnwrap(response.body)
            XCTAssertEqual(String(buffer: body), "1234567890")
        }
        app.XCTExecute(uri: "/", method: .GET, headers: ["Authorization": "Basic 1234567890"]) { response in
            XCTAssertEqual(response.status, .notFound)
        }
    }

    func testBasic() {
        let app = HBApplication(testing: .embedded)
        app.router.get { request -> String? in
            return request.auth.basic.map { "\($0.username):\($0.password)" }
        }
        app.XCTStart()
        defer { app.XCTStop() }

        let basic = "adam:password"
        let base64 = String(base64Encoding: basic.utf8)
        app.XCTExecute(uri: "/", method: .GET, headers: ["Authorization": "Basic \(base64)"]) { response in
            let body = try XCTUnwrap(response.body)
            XCTAssertEqual(String(buffer: body), basic)
        }
    }

    func testAuth() {
        struct User: HBAuthenticatable {
            let name: String
        }
        let app = HBApplication(testing: .embedded)
        app.router.get { request -> HTTPResponseStatus in
            request.auth.login(User(name: "Test"))
            XCTAssert(request.auth.has(User.self))
            XCTAssertEqual(request.auth.get(User.self)?.name, "Test")
            request.auth.logout(User.self)
            XCTAssertFalse(request.auth.has(User.self))
            XCTAssertNil(request.auth.get(User.self))
            return .accepted
        }

        app.XCTStart()
        defer { app.XCTStop() }

        app.XCTExecute(uri: "/", method: .GET) { response in
            XCTAssertEqual(response.status, .accepted)
        }
    }

    func testLogin() {
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
            guard request.auth.has(User.self) else { return .unauthorized }
            return .ok
        }

        app.XCTStart()
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

    func testHOTP() {
        // test against RFC4226 example values https://tools.ietf.org/html/rfc4226#page-32
        let secret = "12345678901234567890"
        XCTAssertEqual(HOTP(secret: secret).compute(counter: 0), 755_224)
        XCTAssertEqual(HOTP(secret: secret).compute(counter: 1), 287_082)
        XCTAssertEqual(HOTP(secret: secret).compute(counter: 2), 359_152)
        XCTAssertEqual(HOTP(secret: secret).compute(counter: 3), 969_429)
        XCTAssertEqual(HOTP(secret: secret).compute(counter: 4), 338_314)
        XCTAssertEqual(HOTP(secret: secret).compute(counter: 5), 254_676)
        XCTAssertEqual(HOTP(secret: secret).compute(counter: 6), 287_922)
        XCTAssertEqual(HOTP(secret: secret).compute(counter: 7), 162_583)
        XCTAssertEqual(HOTP(secret: secret).compute(counter: 8), 399_871)
        XCTAssertEqual(HOTP(secret: secret).compute(counter: 9), 520_489)
    }

    func testTOTP() {
        // test against RFC6238 example values https://tools.ietf.org/html/rfc6238#page-15
        let secret = "12345678901234567890"

        let dateFormatter = DateFormatter()
        dateFormatter.locale = Locale(identifier: "en_US_POSIX")
        dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
        dateFormatter.timeZone = TimeZone(secondsFromGMT: 0)

        XCTAssertEqual(TOTP(secret: secret, length: 8).compute(date: dateFormatter.date(from: "1970-01-01T00:00:59Z")!), 94_287_082)
        XCTAssertEqual(TOTP(secret: secret, length: 8).compute(date: dateFormatter.date(from: "2005-03-18T01:58:29Z")!), 7_081_804)
        XCTAssertEqual(TOTP(secret: secret, length: 8).compute(date: dateFormatter.date(from: "2005-03-18T01:58:31Z")!), 14_050_471)
        XCTAssertEqual(TOTP(secret: secret, length: 8).compute(date: dateFormatter.date(from: "2009-02-13T23:31:30Z")!), 89_005_924)
        XCTAssertEqual(TOTP(secret: secret, length: 8).compute(date: dateFormatter.date(from: "2033-05-18T03:33:20Z")!), 69_279_037)
        XCTAssertEqual(TOTP(secret: secret, length: 8).compute(date: dateFormatter.date(from: "2603-10-11T11:33:20Z")!), 65_353_130)
    }

    func testAuthenticatorURL() {
        let secret = "HB12345678901234567890"
        let url = TOTP(secret: secret, length: 8).createAuthenticatorURL(label: "TOTP test", issuer: "Hummingbird")
        XCTAssertEqual(url, "otpauth://totp/TOTP%20test?secret=JBBDCMRTGQ2TMNZYHEYDCMRTGQ2TMNZYHEYA&issuer=Hummingbird&digits=8")
    }
}
