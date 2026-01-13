//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import Hummingbird
import HummingbirdAuth
import HummingbirdAuthTesting
import HummingbirdBcrypt
import HummingbirdTesting
import NIOPosix
import Testing

struct BcryptTests {
    @Test func testBcrypt() {
        let hash = Bcrypt.hash("password")
        #expect(Bcrypt.verify("password", hash: hash))
    }

    @Test func testBcryptFalse() {
        let hash = Bcrypt.hash("password")
        #expect(!Bcrypt.verify("password1", hash: hash))
    }

    @Test func testMultipleBcrypt() async throws {
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
