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

import HummingbirdOTP
import XCTest

final class OTPTests: XCTestCase {
    func randomBuffer(size: Int) -> [UInt8] {
        var data = [UInt8](repeating: 0, count: size)
        data = data.map { _ in UInt8.random(in: 0...255) }
        return data
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
