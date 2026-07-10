import Foundation
import Testing

@testable import PasskeyCore

@Suite struct CBORTests {
  @Test func decodesDeterministicValues() throws {
    #expect(try CBORDecoder.decode(Data([0x00])) == .unsigned(0))
    #expect(try CBORDecoder.decode(Data([0x20])) == .negative(-1))
    #expect(
      try CBORDecoder.decode(Data([0x43, 0x01, 0x02, 0x03])) == .byteString(Data([1, 2, 3])))
    #expect(try CBORDecoder.decode(Data([0x62, 0x68, 0x69])) == .textString("hi"))
    #expect(try CBORDecoder.decode(Data([0x82, 0xf5, 0xf6])) == .array([.boolean(true), .null]))
  }

  @Test func decodesPrefixAndReportsConsumedBytes() throws {
    let result = try CBORDecoder.decodePrefix(Data([0x18, 0x18, 0xff]))

    #expect(result.value == .unsigned(24))
    #expect(result.consumed == 2)
  }

  @Test func rejectsNonCanonicalAndIndefiniteLengths() {
    #expect(throws: CBORError.nonCanonicalInteger) {
      try CBORDecoder.decode(Data([0x18, 0x01]))
    }
    #expect(throws: CBORError.indefiniteLengthNotAllowed) {
      try CBORDecoder.decode(Data([0x9f, 0xff]))
    }
  }

  @Test func rejectsDuplicateAndIncorrectlyOrderedMapKeys() {
    #expect(throws: CBORError.duplicateMapKey) {
      try CBORDecoder.decode(Data([0xa2, 0x01, 0x00, 0x01, 0x01]))
    }
    #expect(throws: CBORError.nonCanonicalMapOrder) {
      try CBORDecoder.decode(Data([0xa2, 0x02, 0x00, 0x01, 0x00]))
    }
  }

  @Test func appliesDepthAndStringLimits() {
    let depthLimits = CBORLimits(maximumDepth: 1)
    #expect(throws: CBORError.nestingTooDeep(maximum: 1)) {
      try CBORDecoder.decode(Data([0x81, 0x81, 0x00]), limits: depthLimits)
    }

    let stringLimits = CBORLimits(maximumByteStringBytes: 2)
    #expect(throws: CBORError.stringTooLarge(actual: 3, maximum: 2)) {
      try CBORDecoder.decode(Data([0x43, 0x01, 0x02, 0x03]), limits: stringLimits)
    }
  }
}
