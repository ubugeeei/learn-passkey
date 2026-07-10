import Foundation

public enum ByteCursorError: Error, Equatable, Sendable {
  case outOfBounds(requested: Int, remaining: Int)
  case integerOverflow
  case trailingBytes(count: Int)
}

/// A bounds-checked reader for network-byte-order WebAuthn structures.
public struct ByteCursor: Sendable {
  private let bytes: Data
  public private(set) var offset: Int

  public init(_ bytes: Data, offset: Int = 0) throws {
    guard bytes.indices.contains(offset) || offset == bytes.endIndex else {
      throw ByteCursorError.outOfBounds(
        requested: offset,
        remaining: bytes.count
      )
    }
    self.bytes = bytes
    self.offset = offset
  }

  public var remainingCount: Int {
    bytes.count - offset
  }

  public var isAtEnd: Bool {
    remainingCount == 0
  }

  public mutating func readByte() throws -> UInt8 {
    guard remainingCount >= 1 else {
      throw ByteCursorError.outOfBounds(requested: 1, remaining: remainingCount)
    }
    defer { offset += 1 }
    return bytes[offset]
  }

  public mutating func read(_ count: Int) throws -> Data {
    guard count >= 0, count <= remainingCount else {
      throw ByteCursorError.outOfBounds(requested: count, remaining: remainingCount)
    }
    let end = offset + count
    defer { offset = end }
    return bytes.subdata(in: offset..<end)
  }

  public mutating func readUInt16() throws -> UInt16 {
    let value = try read(2)
    return value.reduce(UInt16.zero) { ($0 << 8) | UInt16($1) }
  }

  public mutating func readUInt32() throws -> UInt32 {
    let value = try read(4)
    return value.reduce(UInt32.zero) { ($0 << 8) | UInt32($1) }
  }

  public mutating func requireEnd() throws {
    guard isAtEnd else {
      throw ByteCursorError.trailingBytes(count: remainingCount)
    }
  }
}
