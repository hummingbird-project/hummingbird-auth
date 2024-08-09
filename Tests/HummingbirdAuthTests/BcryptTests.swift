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

import Bcrypt
import Hummingbird
import HummingbirdAuth
import HummingbirdAuthTesting
import HummingbirdTesting
import NIOPosix
import XCTest

final class BcryptTests: XCTestCase {
    func testBcrypt() {
        let hash = Bcrypt.hash("password")
        XCTAssert(Bcrypt.verify("password", hash: hash))
    }

    func testBcryptFalse() {
        let hash = Bcrypt.hash("password")
        XCTAssertFalse(Bcrypt.verify("password1", hash: hash))
    }

    func testMultipleBcrypt() async throws {
        struct VerifyFailError: Error {}

        try await withThrowingTaskGroup(of: Void.self) { group in
            for i in 0..<8 {
                group.addTask {
                    let text = "This is a test \(i)"
                    let hash = Bcrypt.hash(text)
                    if Bcrypt.verify(text, hash: hash) {
                        return
                    } else {
                        throw VerifyFailError()
                    }
                }
            }
            try await group.waitForAll()
        }
    }
}
