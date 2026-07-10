import Foundation

/// Structural or policy failure while interpreting a COSE_Key.
public enum COSEKeyError: Error, Equatable, Sendable {
  case expectedMap
  case missingParameter(Int64)
  case invalidParameter(Int64)
  case unsupportedKeyType(Int64)
  case unsupportedAlgorithm(Int64)
  case unsupportedCurve(Int64)
  case invalidCoordinateLength(parameter: Int64, actual: Int)
}

/// A validated ES256 public key encoded as a COSE EC2/P-256 key.
///
/// The lab intentionally accepts one algorithm so algorithm negotiation cannot
/// silently downgrade verification or reinterpret key material.
public struct COSEEC2PublicKey: Equatable, Sendable {
  public static let keyTypeEC2: Int64 = 2
  public static let algorithmES256: Int64 = -7
  public static let curveP256: Int64 = 1

  public let algorithm: Int64
  public let curve: Int64
  public let x: Data
  public let y: Data

  public init(algorithm: Int64, curve: Int64, x: Data, y: Data) throws {
    guard algorithm == Self.algorithmES256 else {
      throw COSEKeyError.unsupportedAlgorithm(algorithm)
    }
    guard curve == Self.curveP256 else {
      throw COSEKeyError.unsupportedCurve(curve)
    }
    guard x.count == 32 else {
      throw COSEKeyError.invalidCoordinateLength(parameter: -2, actual: x.count)
    }
    guard y.count == 32 else {
      throw COSEKeyError.invalidCoordinateLength(parameter: -3, actual: y.count)
    }
    self.algorithm = algorithm
    self.curve = curve
    self.x = x
    self.y = y
  }

  /// Extracts mandatory COSE labels and validates their types and lengths.
  public init(cbor: CBORValue) throws {
    guard cbor.mapEntries != nil else { throw COSEKeyError.expectedMap }

    let keyType = try Self.integerParameter(1, in: cbor)
    guard keyType == Self.keyTypeEC2 else {
      throw COSEKeyError.unsupportedKeyType(keyType)
    }

    let algorithm = try Self.integerParameter(3, in: cbor)
    let curve = try Self.integerParameter(-1, in: cbor)
    let x = try Self.byteStringParameter(-2, in: cbor)
    let y = try Self.byteStringParameter(-3, in: cbor)
    try self.init(algorithm: algorithm, curve: curve, x: x, y: y)
  }

  /// ANSI X9.63 uncompressed point: `0x04 || X || Y`.
  public var x963Representation: Data {
    Data([0x04]) + x + y
  }

  private static func integerParameter(_ label: Int64, in value: CBORValue) throws -> Int64 {
    guard let parameter = value.value(for: cborInteger(label)) else {
      throw COSEKeyError.missingParameter(label)
    }
    switch parameter {
    case .unsigned(let value) where value <= UInt64(Int64.max):
      return Int64(value)
    case .negative(let value):
      return value
    default:
      throw COSEKeyError.invalidParameter(label)
    }
  }

  private static func byteStringParameter(_ label: Int64, in value: CBORValue) throws -> Data {
    guard let parameter = value.value(for: cborInteger(label)) else {
      throw COSEKeyError.missingParameter(label)
    }
    guard case .byteString(let bytes) = parameter else {
      throw COSEKeyError.invalidParameter(label)
    }
    return bytes
  }

  private static func cborInteger(_ value: Int64) -> CBORValue {
    value >= 0 ? .unsigned(UInt64(value)) : .negative(value)
  }
}
