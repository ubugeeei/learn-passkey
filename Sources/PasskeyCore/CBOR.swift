import Foundation

/// A map entry that preserves deterministic CBOR key order.
public struct CBORMapEntry: Equatable, Sendable {
  public let key: CBORValue
  public let value: CBORValue

  public init(key: CBORValue, value: CBORValue) {
    self.key = key
    self.value = value
  }
}

/// The bounded CBOR data model needed by WebAuthn and COSE.
///
/// Maps use ordered entries instead of a Swift dictionary so duplicate and
/// non-canonical keys can be rejected before application lookup.
public indirect enum CBORValue: Equatable, Sendable {
  case unsigned(UInt64)
  case negative(Int64)
  case byteString(Data)
  case textString(String)
  case array([CBORValue])
  case map([CBORMapEntry])
  case tagged(UInt64, CBORValue)
  case boolean(Bool)
  case null

  public var byteString: Data? {
    guard case .byteString(let value) = self else { return nil }
    return value
  }

  public var textString: String? {
    guard case .textString(let value) = self else { return nil }
    return value
  }

  public var mapEntries: [CBORMapEntry]? {
    guard case .map(let entries) = self else { return nil }
    return entries
  }

  public func value(for key: CBORValue) -> CBORValue? {
    mapEntries?.first(where: { $0.key == key })?.value
  }
}

/// Allocation and recursion limits applied before decoding untrusted CBOR.
public struct CBORLimits: Equatable, Sendable {
  public let maximumInputBytes: Int
  public let maximumByteStringBytes: Int
  public let maximumTextStringBytes: Int
  public let maximumCollectionCount: Int
  public let maximumDepth: Int

  public init(
    maximumInputBytes: Int = 64 * 1024,
    maximumByteStringBytes: Int = 32 * 1024,
    maximumTextStringBytes: Int = 8 * 1024,
    maximumCollectionCount: Int = 256,
    maximumDepth: Int = 16
  ) {
    self.maximumInputBytes = maximumInputBytes
    self.maximumByteStringBytes = maximumByteStringBytes
    self.maximumTextStringBytes = maximumTextStringBytes
    self.maximumCollectionCount = maximumCollectionCount
    self.maximumDepth = maximumDepth
  }
}

/// A deterministic-encoding, resource-limit, or structural CBOR failure.
public enum CBORError: Error, Equatable, Sendable {
  case inputTooLarge(actual: Int, maximum: Int)
  case truncated
  case unsupportedAdditionalInformation(UInt8)
  case indefiniteLengthNotAllowed
  case nonCanonicalInteger
  case integerOverflow
  case invalidUTF8
  case stringTooLarge(actual: UInt64, maximum: Int)
  case collectionTooLarge(actual: UInt64, maximum: Int)
  case nestingTooDeep(maximum: Int)
  case duplicateMapKey
  case nonCanonicalMapOrder
  case unsupportedSimpleValue(UInt8)
  case trailingBytes(count: Int)
}

/// A strict decoder for the deterministic CBOR subset used by WebAuthn.
///
/// It accepts definite-length items, enforces the shortest integer/length
/// encoding, rejects duplicate or incorrectly ordered map keys, and applies
/// conservative resource limits before allocating.
public enum CBORDecoder {
  /// Decodes one complete CBOR item and rejects trailing bytes.
  public static func decode(
    _ data: Data,
    limits: CBORLimits = CBORLimits()
  ) throws -> CBORValue {
    let result = try decodePrefix(data, limits: limits)
    guard result.consumed == data.count else {
      throw CBORError.trailingBytes(count: data.count - result.consumed)
    }
    return result.value
  }

  /// Decodes the first CBOR item and reports its encoded length.
  ///
  /// Authenticator data uses this to find the boundary between a COSE public
  /// key and optional extension data without re-encoding either value.
  public static func decodePrefix(
    _ data: Data,
    limits: CBORLimits = CBORLimits()
  ) throws -> (value: CBORValue, consumed: Int) {
    guard data.count <= limits.maximumInputBytes else {
      throw CBORError.inputTooLarge(actual: data.count, maximum: limits.maximumInputBytes)
    }
    var parser = CBORParser(data: data, limits: limits)
    let value = try parser.parse(depth: 0).value
    return (value, parser.offset)
  }
}

private struct CBORParser {
  private let data: Data
  private let limits: CBORLimits
  private(set) var offset = 0

  init(data: Data, limits: CBORLimits) {
    self.data = data
    self.limits = limits
  }

  mutating func parse(depth: Int) throws -> (value: CBORValue, encoded: Data) {
    guard depth <= limits.maximumDepth else {
      throw CBORError.nestingTooDeep(maximum: limits.maximumDepth)
    }

    let start = offset
    let initial = try readByte()
    let majorType = initial >> 5
    let additionalInformation = initial & 0x1f
    let argument = try readArgument(additionalInformation)

    let value: CBORValue
    switch majorType {
    case 0:
      value = .unsigned(argument)
    case 1:
      guard argument <= UInt64(Int64.max) else {
        throw CBORError.integerOverflow
      }
      value = .negative(-1 - Int64(argument))
    case 2:
      try requireStringLimit(argument, maximum: limits.maximumByteStringBytes)
      value = .byteString(try readData(count: try int(argument)))
    case 3:
      try requireStringLimit(argument, maximum: limits.maximumTextStringBytes)
      let encoded = try readData(count: try int(argument))
      guard let string = String(data: encoded, encoding: .utf8) else {
        throw CBORError.invalidUTF8
      }
      value = .textString(string)
    case 4:
      try requireCollectionLimit(argument)
      var items: [CBORValue] = []
      items.reserveCapacity(try int(argument))
      for _ in 0..<argument {
        items.append(try parse(depth: depth + 1).value)
      }
      value = .array(items)
    case 5:
      try requireCollectionLimit(argument)
      var entries: [CBORMapEntry] = []
      entries.reserveCapacity(try int(argument))
      var previousEncodedKey: Data?
      for _ in 0..<argument {
        let parsedKey = try parse(depth: depth + 1)
        if let previousEncodedKey,
          !isOrderedAfter(parsedKey.encoded, previous: previousEncodedKey)
        {
          if entries.contains(where: { $0.key == parsedKey.value }) {
            throw CBORError.duplicateMapKey
          }
          throw CBORError.nonCanonicalMapOrder
        }
        if entries.contains(where: { $0.key == parsedKey.value }) {
          throw CBORError.duplicateMapKey
        }
        previousEncodedKey = parsedKey.encoded
        let parsedValue = try parse(depth: depth + 1).value
        entries.append(CBORMapEntry(key: parsedKey.value, value: parsedValue))
      }
      value = .map(entries)
    case 6:
      value = .tagged(argument, try parse(depth: depth + 1).value)
    case 7:
      switch additionalInformation {
      case 20:
        value = .boolean(false)
      case 21:
        value = .boolean(true)
      case 22:
        value = .null
      default:
        throw CBORError.unsupportedSimpleValue(additionalInformation)
      }
    default:
      preconditionFailure("A CBOR major type always fits in three bits")
    }

    return (value, data.subdata(in: start..<offset))
  }

  private mutating func readArgument(_ additionalInformation: UInt8) throws -> UInt64 {
    switch additionalInformation {
    case 0...23:
      return UInt64(additionalInformation)
    case 24:
      let value = UInt64(try readByte())
      guard value >= 24 else { throw CBORError.nonCanonicalInteger }
      return value
    case 25:
      let value = try readUnsigned(byteCount: 2)
      guard value > UInt8.max else { throw CBORError.nonCanonicalInteger }
      return value
    case 26:
      let value = try readUnsigned(byteCount: 4)
      guard value > UInt16.max else { throw CBORError.nonCanonicalInteger }
      return value
    case 27:
      let value = try readUnsigned(byteCount: 8)
      guard value > UInt32.max else { throw CBORError.nonCanonicalInteger }
      return value
    case 31:
      throw CBORError.indefiniteLengthNotAllowed
    default:
      throw CBORError.unsupportedAdditionalInformation(additionalInformation)
    }
  }

  private mutating func readByte() throws -> UInt8 {
    guard offset < data.count else { throw CBORError.truncated }
    defer { offset += 1 }
    return data[offset]
  }

  private mutating func readUnsigned(byteCount: Int) throws -> UInt64 {
    var value: UInt64 = 0
    for _ in 0..<byteCount {
      value = (value << 8) | UInt64(try readByte())
    }
    return value
  }

  private mutating func readData(count: Int) throws -> Data {
    guard count <= data.count - offset else { throw CBORError.truncated }
    let end = offset + count
    defer { offset = end }
    return data.subdata(in: offset..<end)
  }

  private func int(_ value: UInt64) throws -> Int {
    guard value <= UInt64(Int.max) else { throw CBORError.integerOverflow }
    return Int(value)
  }

  private func requireStringLimit(_ count: UInt64, maximum: Int) throws {
    guard count <= UInt64(maximum) else {
      throw CBORError.stringTooLarge(actual: count, maximum: maximum)
    }
  }

  private func requireCollectionLimit(_ count: UInt64) throws {
    guard count <= UInt64(limits.maximumCollectionCount) else {
      throw CBORError.collectionTooLarge(
        actual: count,
        maximum: limits.maximumCollectionCount
      )
    }
  }

  /// RFC 8949 length-first deterministic ordering for encoded map keys.
  private func isOrderedAfter(_ candidate: Data, previous: Data) -> Bool {
    if candidate.count != previous.count {
      return candidate.count > previous.count
    }
    return previous.lexicographicallyPrecedes(candidate)
  }
}
