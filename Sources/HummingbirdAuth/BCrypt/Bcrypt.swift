import CBcrypt

/// bcrypt is a password-hashing function designed by Niels Provos and David Mazières, based on the Blowfish cipher
/// and presented at USENIX in 1999.[1] Besides incorporating a salt to protect against rainbow table attacks, bcrypt
/// is an adaptive function: over time, the iteration count can be increased to make it slower, so it remains resistant to
/// brute-force search attacks even with increasing computation power. 
public enum Bcrypt {
    /// Generate bcrypt hash from test
    /// - Parameters:
    ///   - text: original text
    ///   - cost: log2 iterations of algorithm
    /// - Returns: Hashed string
    public static func hash(_ text: String, cost: UInt8 = 12) -> String? {
        guard cost >= BCRYPT_MINLOGROUNDS, cost <= 31 else {
            preconditionFailure("Cost should be between 4 and 31")
        }

        guard let salt = bcrypt_gensalt(cost) else { return nil }
        guard let hashedData = bcrypt(text, salt) else { return nil }
        return String(cString: hashedData)
    }
    
    /// Verify text and hash match
    /// - Parameters:
    ///   - text: plain text
    ///   - hash: hashed data
    public static func verify(_ text: String, hash: String) -> Bool {
        // read salt
        let salt = hash.prefix(29)
        guard salt.count == 29 else { return false }
        
        guard let hashedData = bcrypt(text, String(salt)) else { return false }
        let hashString = String(cString: hashedData)
        return hashString == hash
    }
}
