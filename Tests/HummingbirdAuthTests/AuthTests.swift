import XCTest
@testable import HummingbirdAuth

final class AuthTests: XCTestCase {
    func testBcrypt() throws {
        let hash = try XCTUnwrap(Bcrypt.hash("password", numberOfRounds: 30))
        XCTAssert(Bcrypt.verify("password", hash: hash))
    }
}
