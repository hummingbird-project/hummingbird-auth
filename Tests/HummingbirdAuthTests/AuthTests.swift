import XCTest
@testable import HummingbirdAuth

final class AuthTests: XCTestCase {
    func testBcrypt() throws {
        let hash = try XCTUnwrap(Bcrypt.hash("password"))
        XCTAssert(Bcrypt.verify("password", hash: hash))
    }
}
