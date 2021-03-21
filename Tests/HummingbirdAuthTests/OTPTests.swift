import Hummingbird
import HummingbirdAuth
import HummingbirdXCT
import XCTest

final class Base32Tests: XCTestCase {
    func randomBuffer(size: Int) -> [UInt8] {
        var data = [UInt8](repeating: 0, count: size)
        data = data.map { _ in UInt8.random(in: 0...255) }
        return data
    }

    func testBase32EncodeDecode() {
        let data = self.randomBuffer(size: Int.random(in: 4000...8000))
        let base32 = String(base32Encoding: data)
        let data2 = try! base32.base32decoded()
        XCTAssertEqual(data, data2)
    }

    func testEncodeEmptyData() {
        let data = [UInt8]()
        let encodedData: [UInt8] = Base32.encodeBytes(data)
        XCTAssertEqual(encodedData.count, 0)
    }

    func testBase32EncodingArrayOfNulls() {
        let data = Array(repeating: UInt8(0), count: 10)
        let encodedData: [UInt8] = Base32.encodeBytes(data)
        XCTAssertEqual(encodedData, [UInt8]("AAAAAAAAAAAAAAAA".utf8))
    }

    func testBase32EncodingAllTheBytesSequentially() {
        let data = Array(UInt8(0)...UInt8(255))
        let encodedData = Base32.encodeBytes(data)
        XCTAssertEqual(encodedData, [UInt8]("AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPSAIJCEMSCKJRHFAUSUKZMFUXC6MBRGIZTINJWG44DSOR3HQ6T4P2AIFBEGRCFIZDUQSKKJNGE2TSPKBIVEU2UKVLFOWCZLJNVYXK6L5QGCYTDMRSWMZ3INFVGW3DNNZXXA4LSON2HK5TXPB4XU634PV7H7AEBQKBYJBMGQ6EITCULRSGY5D4QSGJJHFEVS2LZRGM2TOOJ3HU7UCQ2FI5EUWTKPKFJVKV2ZLNOV6YLDMVTWS23NN5YXG5LXPF5X274BQOCYPCMLRWHZDE4VS6MZXHM7UGR2LJ5JVOW27MNTWW33TO55X7A4HROHZHF43T6R2PK5PWO33XP6DY7F47U6X3PP6HZ7L57Z7P674".utf8))
    }

    // MARK: Decoding

    func testDecodeEmptyString() throws {
        var decoded: [UInt8]?
        XCTAssertNoThrow(decoded = try Base32.decode(""))
        XCTAssertEqual(decoded?.count, 0)
    }

    func testDecodeEmptyBytes() throws {
        var decoded: [UInt8]?
        XCTAssertNoThrow(decoded = try Base32.decode([]))
        XCTAssertEqual(decoded?.count, 0)
    }

    func testBase32DecodingArrayOfNulls() throws {
        let expected = Array(repeating: UInt8(0), count: 10)
        var decoded: [UInt8]?
        var string = "AAAAAAAAAAAAAAAAA"
        string.makeContiguousUTF8()
        XCTAssertNoThrow(decoded = try Base32.decode(string))
        XCTAssertEqual(decoded, expected)
    }

    func testBase32DecodingAllTheBytesSequentially() {
        let base64 = "AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPSAIJCEMSCKJRHFAUSUKZMFUXC6MBRGIZTINJWG44DSOR3HQ6T4P2AIFBEGRCFIZDUQSKKJNGE2TSPKBIVEU2UKVLFOWCZLJNVYXK6L5QGCYTDMRSWMZ3INFVGW3DNNZXXA4LSON2HK5TXPB4XU634PV7H7AEBQKBYJBMGQ6EITCULRSGY5D4QSGJJHFEVS2LZRGM2TOOJ3HU7UCQ2FI5EUWTKPKFJVKV2ZLNOV6YLDMVTWS23NN5YXG5LXPF5X274BQOCYPCMLRWHZDE4VS6MZXHM7UGR2LJ5JVOW27MNTWW33TO55X7A4HROHZHF43T6R2PK5PWO33XP6DY7F47U6X3PP6HZ7L57Z7P674"

        let expected = Array(UInt8(0)...UInt8(255))
        var decoded: [UInt8]?
        XCTAssertNoThrow(decoded = try Base32.decode(base64.utf8))
        XCTAssertEqual(decoded, expected)
    }

    func testBase32DecodingWithPoop() {
        XCTAssertThrowsError(_ = try Base32.decode("💩".utf8)) { error in
            XCTAssertEqual(error as? Base32.DecodingError, .invalidCharacter(240))
        }
    }

    func testBase32DecodingOneTwoThreeFour() {
        let base64 = "AEBAGBA"
        let bytes: [UInt8] = [1, 2, 3, 4]

        XCTAssertEqual(Base32.encodeString(bytes), base64)
        XCTAssertEqual(try Base32.decode(base64), bytes)
    }

    func testBase32DecodingOneTwoThreeFourFive() {
        let base64 = "AEBAGBAF"
        let bytes: [UInt8] = [1, 2, 3, 4, 5]

        XCTAssertEqual(Base32.encodeString(bytes), base64)
        XCTAssertEqual(try Base32.decode(base64), bytes)
    }

    func testBase32DecodingOneTwoThreeFourFiveSix() {
        let base64 = "AEBAGBAFAY"
        let bytes: [UInt8] = [1, 2, 3, 4, 5, 6]

        XCTAssertEqual(Base32.encodeString(bytes), base64)
        XCTAssertEqual(try Base32.decode(base64), bytes)
    }
}

final class OTPTests: XCTestCase {
    func testHOTP() {
        // test against RFC4226 example values https://tools.ietf.org/html/rfc4226#page-32
        let secret = "12345678901234567890"
        XCTAssertEqual(HOTP(secret: secret).compute(counter: 0), 755_224)
        XCTAssertEqual(HOTP(secret: secret).compute(counter: 1), 287_082)
        XCTAssertEqual(HOTP(secret: secret).compute(counter: 2), 359_152)
        XCTAssertEqual(HOTP(secret: secret).compute(counter: 3), 969_429)
        XCTAssertEqual(HOTP(secret: secret).compute(counter: 4), 338_314)
        XCTAssertEqual(HOTP(secret: secret).compute(counter: 5), 254_676)
        XCTAssertEqual(HOTP(secret: secret).compute(counter: 6), 287_922)
        XCTAssertEqual(HOTP(secret: secret).compute(counter: 7), 162_583)
        XCTAssertEqual(HOTP(secret: secret).compute(counter: 8), 399_871)
        XCTAssertEqual(HOTP(secret: secret).compute(counter: 9), 520_489)
    }

    func testTOTP() {
        // test against RFC6238 example values https://tools.ietf.org/html/rfc6238#page-15
        let secret = "12345678901234567890"

        let dateFormatter = DateFormatter()
        dateFormatter.locale = Locale(identifier: "en_US_POSIX")
        dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
        dateFormatter.timeZone = TimeZone(secondsFromGMT: 0)

        XCTAssertEqual(TOTP(secret: secret, length: 8).compute(date: dateFormatter.date(from: "1970-01-01T00:00:59Z")!), 94_287_082)
        XCTAssertEqual(TOTP(secret: secret, length: 8).compute(date: dateFormatter.date(from: "2005-03-18T01:58:29Z")!), 7_081_804)
        XCTAssertEqual(TOTP(secret: secret, length: 8).compute(date: dateFormatter.date(from: "2005-03-18T01:58:31Z")!), 14_050_471)
        XCTAssertEqual(TOTP(secret: secret, length: 8).compute(date: dateFormatter.date(from: "2009-02-13T23:31:30Z")!), 89_005_924)
        XCTAssertEqual(TOTP(secret: secret, length: 8).compute(date: dateFormatter.date(from: "2033-05-18T03:33:20Z")!), 69_279_037)
        XCTAssertEqual(TOTP(secret: secret, length: 8).compute(date: dateFormatter.date(from: "2603-10-11T11:33:20Z")!), 65_353_130)
    }

    func testAuthenticatorURL() {
        let secret = "HB12345678901234567890"
        let url = TOTP(secret: secret, length: 8).createAuthenticatorURL(label: "TOTP test", issuer: "Hummingbird")
        XCTAssertEqual(url, "otpauth://totp/TOTP%20test?secret=JBBDCMRTGQ2TMNZYHEYDCMRTGQ2TMNZYHEYA&issuer=Hummingbird&digits=8")
    }
}
