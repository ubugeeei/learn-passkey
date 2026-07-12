import Foundation
import Testing

@testable import PasskeyCore

@Suite struct Base64URLTests {
  @Test(
    "RFC 4648 vectors round-trip without padding",
    arguments: Base64URLVector.rfc4648
  )
  func rfc4648VectorsWithoutPadding(vector: Base64URLVector) throws {
    let data = Data(vector.plainText.utf8)
    #expect(Base64URL.encode(data) == vector.encoded)
    #expect(try Base64URL.decode(vector.encoded) == data)
  }

  @Test func usesURLSafeAlphabet() throws {
    let bytes = Data([0xfb, 0xff, 0xff])
    #expect(Base64URL.encode(bytes) == "-___")
    #expect(try Base64URL.decode("-___") == bytes)
  }

  @Test func rejectsNonCanonicalInput() {
    #expect(throws: Base64URLError.containsPadding) {
      try Base64URL.decode("Zg==")
    }
    #expect(throws: Base64URLError.invalidAlphabet) {
      try Base64URL.decode("Z g")
    }
    #expect(throws: Base64URLError.invalidLength) {
      try Base64URL.decode("a")
    }
  }

  @Test func constantTimeComparisonIncludesLength() {
    #expect(Data([1, 2, 3]).constantTimeEquals(Data([1, 2, 3])))
    #expect(!Data([1, 2, 3]).constantTimeEquals(Data([1, 2, 4])))
    #expect(!Data([1, 2, 3]).constantTimeEquals(Data([1, 2, 3, 0])))
  }
}

/// One standards example shown by name when a parameterized test fails.
private struct Base64URLVector: CustomTestStringConvertible, Sendable {
  let plainText: String
  let encoded: String

  var testDescription: String { "\(plainText.debugDescription) → \(encoded.debugDescription)" }

  static let rfc4648 = [
    Base64URLVector(plainText: "", encoded: ""),
    Base64URLVector(plainText: "f", encoded: "Zg"),
    Base64URLVector(plainText: "fo", encoded: "Zm8"),
    Base64URLVector(plainText: "foo", encoded: "Zm9v"),
    Base64URLVector(plainText: "foob", encoded: "Zm9vYg"),
    Base64URLVector(plainText: "fooba", encoded: "Zm9vYmE"),
    Base64URLVector(plainText: "foobar", encoded: "Zm9vYmFy"),
  ]
}
