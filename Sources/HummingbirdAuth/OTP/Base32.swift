@_implementationOnly import CBase32

enum Base32 {
    static func encodeBytes<Buffer: Collection>(bytes: Buffer) -> [UInt8] where Buffer.Element == UInt8 {
        let capacity = (bytes.count * 8 + 4) / 5

        let result = bytes.withContiguousStorageIfAvailable { input -> [UInt8] in
            return [UInt8](unsafeUninitializedCapacity: capacity) { buffer, length in
                let length32 = c_hb_base32_encode(
                    input.baseAddress,
                    numericCast(input.count),
                    buffer.baseAddress,
                    numericCast(capacity)
                )
                length = Int(length32)
            }
        }
        if let result = result {
            return result
        }

        return self.encodeBytes(bytes: Array(bytes))
    }

    static func encodeString<Buffer: Collection>(bytes: Buffer) -> String where Buffer.Element == UInt8 {
        let capacity = (bytes.count * 8 + 4) / 5

        if #available(macOS 11.0, *) {
            let result = bytes.withContiguousStorageIfAvailable { input in
                String(unsafeUninitializedCapacity: capacity) { buffer -> Int in
                    let length32 = c_hb_base32_encode(
                        input.baseAddress,
                        numericCast(input.count),
                        buffer.baseAddress,
                        numericCast(capacity)
                    )
                    return Int(length32)
                }
            }
            if let result = result {
                return result
            }

            return self.encodeString(bytes: Array(bytes))
        } else {
            let bytes: [UInt8] = self.encodeBytes(bytes: bytes)
            return String(decoding: bytes, as: Unicode.UTF8.self)
        }
    }

    static func decode(string encoded: String) -> [UInt8]? {
        struct DecodeError: Error {}

        let capacity = (encoded.utf8.count * 5 + 4) / 8

        return encoded.withCString { charPtr -> [UInt8]? in
            return charPtr.withMemoryRebound(to: UInt8.self, capacity: encoded.utf8.count) { (input) -> [UInt8]? in
                return try? [UInt8](unsafeUninitializedCapacity: capacity) { buffer, length in
                    let length32 = c_hb_base32_decode(
                        input,
                        buffer.baseAddress,
                        numericCast(capacity)
                    )
                    guard length32 != -1 else { throw DecodeError() }
                    length = Int(length32)
                }
            }
        }
    }
}

extension String {
    public init<Buffer: Collection>(base32Encoding bytes: Buffer) where Buffer.Element == UInt8
    {
        self = Base32.encodeString(bytes: bytes)
    }

    public func base32decoded() -> [UInt8]? {
        Base32.decode(string: self)
    }

}
