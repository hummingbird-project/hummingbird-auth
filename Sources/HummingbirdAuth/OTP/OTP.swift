//===----------------------------------------------------------------------===//
//
// This source file is part of the Hummingbird server framework project
//
// Copyright (c) 2021-2021 the Hummingbird authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See hummingbird/CONTRIBUTORS.txt for the list of Hummingbird authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import ExtrasBase64
import Foundation

/// HashFunction used in OTP generation
public enum OTPHashFunction: String {
    case sha1 = "SHA1"
    case sha256 = "SHA256"
    case sha512 = "SHA512"
}

/// One time password computation. A one time password is only valid for one login session. OTPs avoid a
/// number of shortcomings that are associated with traditional (static) password-based authentication. OTP
/// generation algorithms typically make use of pseudorandomness or randomness, making prediction of successor
/// OTPs by an attacker difficult, and also cryptographic hash functions, which can be used to derive a value but
/// are hard to reverse and therefore difficult for an attacker to obtain the data that was used for the hash. This is
/// necessary because otherwise it would be easy to predict future OTPs by observing previous ones.
///
/// OTPs are commonly used as the second part of two-factor authentication.
protocol OTP {
    /// Shared secret
    var secret: String { get }
    /// Length of OTP generated
    var length: Int { get }
    /// Hash function used to generate OTP
    var hashFunction: OTPHashFunction { get }
}

extension OTP {
    /// Create Authenticator URL for OTP generator
    ///
    /// - Parameters:
    ///   - algorithmName: Name of algorithm
    ///   - label: Label for URL
    ///   - issuer: Who issued the URL
    ///   - parameters: additional parameters
    func createAuthenticatorURL(algorithmName: String, label: String, issuer: String?, parameters: [String: String]) -> String {
        let base32 = String(base32Encoding: secret.utf8)
        let label = label.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? label
        let issuer = issuer?.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? issuer
        var url = "otpauth://\(algorithmName)/\(label)?secret=\(base32)"
        if let issuer = issuer {
            url += "&issuer=\(issuer)"
        }
        url += parameters
            .map { "&\($0.key)=\($0.value)" }
            .joined()
        return url
    }

    /// compute OTP. Converts hashFunction
    func compute(message: [UInt8]) -> Int {
        switch hashFunction {
        case .sha1:
            return self.compute(message: message, hashFunction: Insecure.SHA1())
        case .sha256:
            return self.compute(message: message, hashFunction: SHA256())
        case .sha512:
            return self.compute(message: message, hashFunction: SHA512())
        }
    }

    /// compute OTP
    func compute<H: Crypto.HashFunction>(message: [UInt8], hashFunction: H) -> Int {
        let sha1 = HMAC<H>.authenticationCode(for: message, using: SymmetricKey(data: [UInt8](secret.utf8)))
        let truncation = sha1.withUnsafeBytes { bytes -> Int in
            let offset = Int(bytes[bytes.count - 1] & 0xF)
            var v = Int(bytes[offset] & 0x7F) << 24
            v += Int(bytes[offset + 1]) << 16
            v += Int(bytes[offset + 2]) << 8
            v += Int(bytes[offset + 3])
            return v
        }
        func pow(_ value: Int, _ power: Int) -> Int {
            return repeatElement(value, count: power).reduce(1, *)
        }
        return truncation % pow(10, length)
    }
}

/// A counter based one time password (OTP)
///
/// A HOTP uses a counter as the message when computing the OTP. Everytime the user
/// successfully logs in the server and client should update the commonly stored counter so
/// the next login will require a new password.
public struct HOTP: OTP {
    public let secret: String
    public let length: Int
    public let hashFunction: OTPHashFunction

    /// Initialize HOTP
    ///
    /// If you are using the Google Authenticator you should choose the default values for length and hashFunction
    ///
    /// - Parameters:
    ///   - secret: Secret known by client and server
    ///   - length: Length of password
    ///   - hashFunction: Hash function to use
    public init(secret: String, length: Int = 6, hashFunction: OTPHashFunction = .sha1) {
        self.secret = secret
        self.length = length
        self.hashFunction = hashFunction
    }

    /// Compute a HOTP.
    /// - Parameters:
    ///   - counter: counter to use
    /// - Returns: HOTP password
    public func compute(counter: UInt64) -> Int {
        self.compute(message: counter.bigEndian.bytes)
    }

    /// Create Authenticator URL for HOTP generator
    ///
    /// OTP is used commonly with authenticator apps on the phone. The Authenticator apps require your
    /// secret to be Base32 encoded when you supply it. You can either supply the base32 encoded secret
    /// to be copied into the authenticator app or generate a QR Code to be scanned. This generates the
    /// URL you should create your QR Code from.
    ///
    /// - Parameters:
    ///   - label: Label for URL
    ///   - issuer: Who issued the URL
    public func createAuthenticatorURL(label: String, issuer: String? = nil) -> String {
        var parameters: [String: String] = [:]
        if self.length != 6 {
            parameters["digits"] = String(describing: self.length)
        }
        if self.hashFunction != .sha1 {
            parameters["algorithm"] = self.hashFunction.rawValue
        }
        return self.createAuthenticatorURL(algorithmName: "totp", label: label, issuer: issuer, parameters: parameters)
    }
}

/// A time based one time password (OTP)
///
/// A TOTP uses UNIX time ie the number of seconds since 1970 divided by a time step (normally
/// 30 seconds) as the counter in the OTP computation. This means each password is only ever
/// valid for the timeStep and a new password will be generated after that period.
public struct TOTP: OTP {
    public let secret: String
    public let length: Int
    public let hashFunction: OTPHashFunction
    public let timeStep: Int

    /// Initialize TOTP
    ///
    /// If you are using the Google Authenticator you should choose the default values for length, timeStep and hashFunction
    ///
    /// - Parameters:
    ///   - secret: Secret known by client and server
    ///   - length: Length of password
    ///   - timeStep: Time between each new code
    ///   - hashFunction: Hash function to use
    public init(secret: String, length: Int = 6, timeStep: Int = 30, hashFunction: OTPHashFunction = .sha1) {
        self.secret = secret
        self.length = length
        self.timeStep = timeStep
        self.hashFunction = hashFunction
    }

    /// Compute a TOTP
    ///
    /// - Parameters:
    ///   - date: Date to generate TOTP for
    /// - Returns: TOTP password
    public func compute(date: Date = Date()) -> Int {
        let timeInterval = date.timeIntervalSince1970
        let value = UInt64(timeInterval / Double(self.timeStep))
        return self.compute(message: value.bigEndian.bytes)
    }

    /// Create Authenticator URL for TOTP generator
    ///
    /// OTP is used commonly with authenticator apps on the phone. The Authenticator apps require your
    /// secret to be Base32 encoded when you supply it. You can either supply the base32 encoded secret
    /// to be copied into the authenticator app or generate a QR Code to be scanned. This generates the
    /// URL you should create your QR Code from.
    ///
    /// - Parameters:
    ///   - label: Label for URL
    ///   - issuer: Who issued the URL
    public func createAuthenticatorURL(label: String, issuer: String? = nil) -> String {
        var parameters: [String: String] = [:]
        if self.length != 6 {
            parameters["digits"] = String(describing: self.length)
        }
        if self.hashFunction != .sha1 {
            parameters["algorithm"] = self.hashFunction.rawValue
        }
        if self.timeStep != 30 {
            parameters["period"] = String(describing: self.timeStep)
        }
        return self.createAuthenticatorURL(algorithmName: "totp", label: label, issuer: issuer, parameters: parameters)
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
