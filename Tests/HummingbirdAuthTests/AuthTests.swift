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
        let data = self.randomBuffer(size: 6002)
        let base32 = String(base32Encoding: data)
        let data2 = base32.base32decoded()
        XCTAssertEqual(data, data2)
    }

    func testHOTP() {
        // test against RFC4226 example values https://tools.ietf.org/html/rfc4226#page-32
        let secret = "12345678901234567890"
        XCTAssertEqual(OTP.computeHOTP(counter: 0, secret: secret), 755_224)
        XCTAssertEqual(OTP.computeHOTP(counter: 1, secret: secret), 287_082)
        XCTAssertEqual(OTP.computeHOTP(counter: 2, secret: secret), 359_152)
        XCTAssertEqual(OTP.computeHOTP(counter: 3, secret: secret), 969_429)
        XCTAssertEqual(OTP.computeHOTP(counter: 4, secret: secret), 338_314)
        XCTAssertEqual(OTP.computeHOTP(counter: 5, secret: secret), 254_676)
        XCTAssertEqual(OTP.computeHOTP(counter: 6, secret: secret), 287_922)
        XCTAssertEqual(OTP.computeHOTP(counter: 7, secret: secret), 162_583)
        XCTAssertEqual(OTP.computeHOTP(counter: 8, secret: secret), 399_871)
        XCTAssertEqual(OTP.computeHOTP(counter: 9, secret: secret), 520_489)
    }

    func testTOTP() {
        // test against RFC6238 example values https://tools.ietf.org/html/rfc6238#page-15
        let secret = "12345678901234567890"

        let dateFormatter = DateFormatter()
        dateFormatter.locale = Locale(identifier: "en_US_POSIX")
        dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
        dateFormatter.timeZone = TimeZone(secondsFromGMT: 0)

        XCTAssertEqual(OTP.computeTOTP(date: dateFormatter.date(from: "1970-01-01T00:00:59Z")!, secret: secret, length: 8), 94_287_082)
        XCTAssertEqual(OTP.computeTOTP(date: dateFormatter.date(from: "2005-03-18T01:58:29Z")!, secret: secret, length: 8), 7_081_804)
        XCTAssertEqual(OTP.computeTOTP(date: dateFormatter.date(from: "2005-03-18T01:58:31Z")!, secret: secret, length: 8), 14_050_471)
        XCTAssertEqual(OTP.computeTOTP(date: dateFormatter.date(from: "2009-02-13T23:31:30Z")!, secret: secret, length: 8), 89_005_924)
        XCTAssertEqual(OTP.computeTOTP(date: dateFormatter.date(from: "2033-05-18T03:33:20Z")!, secret: secret, length: 8), 69_279_037)
        XCTAssertEqual(OTP.computeTOTP(date: dateFormatter.date(from: "2603-10-11T11:33:20Z")!, secret: secret, length: 8), 65_353_130)
    }

    func testAuthenticatorURL() {
        let secret = "HB12345678901234567890"
        let url = OTP.createAuthenticatorURL(for: secret, label: "TOTP test", issuer: "Hummingbird", algorithm: .totp)
        XCTAssertEqual(url, "otpauth://totp/TOTP%20test?secret=JBBDCMRTGQ2TMNZYHEYDCMRTGQ2TMNZYHEYA&issuer=Hummingbird")
    }

    func testHOTP2() {
        let secret = "HB12345678901234567890"
        print((0...10).map { OTP.computeHOTP(counter: $0, secret: secret) })
    }
}
