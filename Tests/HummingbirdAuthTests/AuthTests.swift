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
        let data = randomBuffer(size: 6002)
        let base32 = String(base32Encoding: data)
        let data2 = base32.base32decoded()
        XCTAssertEqual(data, data2)
    }
    
    func testHOTP() {
        // test against RFC4226 example values https://tools.ietf.org/html/rfc4226#page-32
        let secret = "12345678901234567890"
        XCTAssertEqual(OTP.hotp(counter: 0, secret: secret), 755224)
        XCTAssertEqual(OTP.hotp(counter: 1, secret: secret), 287082)
        XCTAssertEqual(OTP.hotp(counter: 2, secret: secret), 359152)
        XCTAssertEqual(OTP.hotp(counter: 3, secret: secret), 969429)
        XCTAssertEqual(OTP.hotp(counter: 4, secret: secret), 338314)
        XCTAssertEqual(OTP.hotp(counter: 5, secret: secret), 254676)
        XCTAssertEqual(OTP.hotp(counter: 6, secret: secret), 287922)
        XCTAssertEqual(OTP.hotp(counter: 7, secret: secret), 162583)
        XCTAssertEqual(OTP.hotp(counter: 8, secret: secret), 399871)
        XCTAssertEqual(OTP.hotp(counter: 9, secret: secret), 520489)
    }

    func testTOTP() {
        // test against RFC6238 example values https://tools.ietf.org/html/rfc6238#page-15
        let secret = "12345678901234567890"
        
        let dateFormatter = DateFormatter()
        dateFormatter.locale = Locale(identifier: "en_US_POSIX")
        dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
        dateFormatter.timeZone = TimeZone(secondsFromGMT: 0)

        XCTAssertEqual(OTP.totp(date: dateFormatter.date(from: "1970-01-01T00:00:59Z")!, secret: secret, length: 8), 94287082)
        XCTAssertEqual(OTP.totp(date: dateFormatter.date(from: "2005-03-18T01:58:29Z")!, secret: secret, length: 8), 7081804)
        XCTAssertEqual(OTP.totp(date: dateFormatter.date(from: "2005-03-18T01:58:31Z")!, secret: secret, length: 8), 14050471)
        XCTAssertEqual(OTP.totp(date: dateFormatter.date(from: "2009-02-13T23:31:30Z")!, secret: secret, length: 8), 89005924)
        XCTAssertEqual(OTP.totp(date: dateFormatter.date(from: "2033-05-18T03:33:20Z")!, secret: secret, length: 8), 69279037)
        XCTAssertEqual(OTP.totp(date: dateFormatter.date(from: "2603-10-11T11:33:20Z")!, secret: secret, length: 8), 65353130)
    }
}
