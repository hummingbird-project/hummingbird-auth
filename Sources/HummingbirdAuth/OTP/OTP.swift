import Crypto
import Foundation

/// One time password computation. A one time password is only valid for one login session. OTPs avoid a
/// number of shortcomings that are associated with traditional (static) password-based authentication. OTP
/// generation algorithms typically make use of pseudorandomness or randomness, making prediction of successor
/// OTPs by an attacker difficult, and also cryptographic hash functions, which can be used to derive a value but
/// are hard to reverse and therefore difficult for an attacker to obtain the data that was used for the hash. This is
/// necessary because otherwise it would be easy to predict future OTPs by observing previous ones.
///
/// OTPs are commonly used as the second part of two-factor authentication.
public enum OTP {
    static func compute(message: [UInt8], secret: String, length: Int = 6) -> Int {
        let sha1 = HMAC<Insecure.SHA1>.authenticationCode(for: message, using: SymmetricKey(data: [UInt8](secret.utf8)))
        let truncation = sha1.withUnsafeBytes { bytes -> Int in
            let offset = Int(bytes[bytes.count-1] & 0xf)
            var v: Int = Int(bytes[offset] & 0x7f) << 24
            v += Int(bytes[offset+1]) << 16
            v += Int(bytes[offset+2]) << 8
            v += Int(bytes[offset+3])
            return v
        }
        func pow(_ value: Int, _ power: Int) -> Int {
            return repeatElement(value, count: power).reduce(1, *)
        }
        return truncation % pow(10, length)
    }

    /// Compute a HOTP.
    ///
    /// A HOTP uses a counter as the message when computing the OTP. Everytime the user
    /// successfully logs in the server and client should update the commonly stored counter so
    /// the next login will require a new password.
    /// - Parameters:
    ///   - counter: counter to use
    ///   - secret: Secret known by client and server
    ///   - length: Length of password
    /// - Returns: OTP password
    public static func hotp(counter: UInt64, secret: String, length: Int = 6) -> Int {
        compute(message: counter.bigEndian.bytes, secret: secret, length: length)
    }

    /// Compute a TOTP
    ///
    /// A TOTP uses UNIX time ie the number of seconds since 1970 divided by a time step (normally
    /// 30 seconds) as the counter in the OTP computation. This means each password is only ever
    /// valid for the timeStep and a new password will be generated after that period.
    ///
    /// TOTP is used commonly with authenticator apps on the phone. Google Authenticator requires your
    /// secret to be Base32 encoded when you supply it. You can either supply the base32 encoded secret
    /// to be copied into the authenticator app or generate a QR Code to be scanned. The address the QR
    /// Code must encode is as follows
    /// ```
    /// otpauth://totp/<label>?secret=<Base32 encoded secret>&issuer=<issuer>
    /// ```
    /// You need to provide a label, Base32 encoded secret and an issuer.
    ///
    /// - Parameters:
    ///   - date: Date to generate TOTP for
    ///   - secret: Secret known by client and server
    ///   - length: Length of password
    ///   - timeStep: Time between each new code
    /// - Returns: OTP password
    public static func totp(date: Date = Date(), secret: String, length: Int = 6, timeStep: Int = 30) -> Int {
        let timeInterval = date.timeIntervalSince1970
        return hotp(counter: UInt64(timeInterval/Double(timeStep)), secret: secret, length: length)
    }
}

extension FixedWidthInteger {
    /// Return fixed width integer as an array of bytes
    var bytes: [UInt8] {
        var v = self
        return .init(&v, count: MemoryLayout<Self>.size)
    }
}

extension Array where Element == UInt8 {
    /// Construct Array of UInt8 by copying memory
    init(_ bytes: UnsafeRawPointer, count: Int) {
        self.init(unsafeUninitializedCapacity: count) { buffer, c in
            for i in 0..<count {
                buffer[i] = bytes.load(fromByteOffset: i, as: UInt8.self)
            }
            c = count
        }
    }
}
