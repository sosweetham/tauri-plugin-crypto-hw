import XCTest

@testable import tauri_plugin_crypto_hw

final class SealedStringTests: XCTestCase {
    func testRoundTripsEveryByte() throws {
        for bytes in [Data(), Data([0]), Data([0xff, 0x00, 0xfe, 0x01]), Data((0...255).map { UInt8($0) })] {
            let sealed = formatSealed(bytes)
            XCTAssertTrue(sealed.hasPrefix("\(sealScheme):"))
            XCTAssertEqual(try parseSealed(sealed), bytes)
        }
    }

    func testFormatsWithoutPaddingOrUrlUnsafeCharacters() {
        let sealed = formatSealed(Data([0xfb, 0xff, 0xbf, 0xfe]))
        XCTAssertFalse(sealed.contains("="))
        XCTAssertFalse(sealed.contains("+"))
        XCTAssertFalse(sealed.contains("/"))
    }

    func testRefusesAStringThatIsNotOurs() {
        XCTAssertThrowsError(try parseSealed("ecies-p256")) { error in
            XCTAssertEqual(error as? CryptoPluginError, .malformedSecret)
        }
        XCTAssertThrowsError(try parseSealed("ecies-p256:not base64")) { error in
            XCTAssertEqual(error as? CryptoPluginError, .malformedSecret)
        }
    }

    func testRefusesAStringSealedSomewhereElse() {
        for sealed in ["aes-gcm-keystore:QUJD", "dpapi:QUJD", ":QUJD"] {
            XCTAssertThrowsError(try parseSealed(sealed)) { error in
                XCTAssertEqual(error as? CryptoPluginError, .foreignSecret, sealed)
            }
        }
    }
}
