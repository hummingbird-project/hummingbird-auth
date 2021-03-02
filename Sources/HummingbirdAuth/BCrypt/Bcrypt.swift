@_implementationOnly import CBcrypt

/// Bcrypt is a password-hashing function designed by Niels Provos and David Mazières, based on the Blowfish cipher
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
        // can guarantee salt if non nil
        let salt = csalt.withUnsafeBufferPointer {
            c_hb_bcrypt_gensalt_with_csalt(cost, $0.baseAddress)!
        }

        // can guarantee hash data is valid as salt was created correctly
        let hashedData = c_hb_bcrypt(text, salt)!
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
