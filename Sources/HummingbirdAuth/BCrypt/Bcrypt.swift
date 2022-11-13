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

@_implementationOnly import CBcrypt

/// Bcrypt password hashing function
///
/// The Bcrypt hashing function was designed by Niels Provos and David Mazières, based on the Blowfish cipher
/// and presented at USENIX in 1999.[1] Besides incorporating a salt to protect against rainbow table attacks, bcrypt
/// is an adaptive function: over time, the iteration count can be increased to make it slower, so it remains resistant to
/// brute-force search attacks even with increasing computation power.
public enum Bcrypt {
    /// Generate bcrypt hash from test
    /// - Parameters:
    ///   - text: original text
    ///   - cost: log2 iterations of algorithm
    /// - Returns: Hashed string
    public static func hash(_ text: String, cost: UInt8 = 12) -> String {
        guard cost >= BCRYPT_MINLOGROUNDS, cost <= 31 else {
            preconditionFailure("Cost should be between 4 and 31")
        }

        // create random salt here, instead of using C as arc4random_buf is not always available
        let csalt: [UInt8] = (0..<BCRYPT_MAXSALT).map { _ in UInt8.random(in: .min ... .max) }
        let salt = [CChar](unsafeUninitializedCapacity: Int(BCRYPT_SALTSPACE)) { bytes, count in
            count = Int(BCRYPT_SALTSPACE)
            _ = c_hb_bcrypt_initsalt_with_csalt(Int32(cost), bytes.baseAddress, Int(BCRYPT_SALTSPACE), csalt)
        }

        // create hashed data
        let nullEndedHashSpace = Int(BCRYPT_HASHSPACE + 1)
        let hashedData = [CChar](unsafeUninitializedCapacity: nullEndedHashSpace) { bytes, count in
            count = nullEndedHashSpace
            _ = c_hb_bcrypt_hashpass(text, salt, bytes.baseAddress, Int(BCRYPT_HASHSPACE))
            bytes.baseAddress?[nullEndedHashSpace - 1] = 0
        }

        return String(cString: hashedData)
    }

    /// Verify text and hash match
    /// - Parameters:
    ///   - text: plain text
    ///   - hash: hashed data
    public static func verify(_ text: String, hash: String) -> Bool {
        return c_hb_bcrypt_checkpass(text, hash) == 0
    }
}
