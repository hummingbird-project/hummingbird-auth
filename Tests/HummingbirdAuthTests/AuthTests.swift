import Hummingbird
import HummingbirdAuth
import HummingbirdXCT
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
}
