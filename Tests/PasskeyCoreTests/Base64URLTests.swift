import Foundation
import Testing

@testable import PasskeyCore

@Suite struct Base64URLTests {
  @Test func rfc4648VectorsWithoutPadding() throws {
    let vectors = [
      ("", ""),
      ("f", "Zg"),
      ("fo", "Zm8"),
      ("foo", "Zm9v"),
      ("foob", "Zm9vYg"),
      ("fooba", "Zm9vYmE"),
      ("foobar", "Zm9vYmFy"),
    ]

    for (plain, encoded) in vectors {
      let data = Data(plain.utf8)
      #expect(Base64URL.encode(data) == encoded)
      #expect(try Base64URL.decode(encoded) == data)
    }
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
