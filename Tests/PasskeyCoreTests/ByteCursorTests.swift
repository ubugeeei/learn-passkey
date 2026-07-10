import Foundation
import Testing

@testable import PasskeyCore

@Suite struct ByteCursorTests {
  @Test func readsNetworkByteOrder() throws {
    var cursor = try ByteCursor(Data([0x01, 0x02, 0x03, 0x04, 0xaa]))

    #expect(try cursor.readUInt32() == 0x0102_0304)
    #expect(try cursor.readByte() == 0xaa)
    try cursor.requireEnd()
  }

  @Test func doesNotAdvanceAfterOutOfBoundsRead() throws {
    var cursor = try ByteCursor(Data([0x01]))

    #expect(throws: ByteCursorError.outOfBounds(requested: 2, remaining: 1)) {
      try cursor.read(2)
    }
    #expect(cursor.offset == 0)
    #expect(try cursor.readByte() == 1)
  }

  @Test func reportsTrailingBytes() throws {
    var cursor = try ByteCursor(Data([0x01, 0x02]))
    _ = try cursor.readByte()

    #expect(throws: ByteCursorError.trailingBytes(count: 1)) {
      try cursor.requireEnd()
    }
  }
}
