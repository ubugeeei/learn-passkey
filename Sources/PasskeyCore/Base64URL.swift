import Foundation

public enum Base64URLError: Error, Equatable, Sendable {
  case containsPadding
  case invalidAlphabet
  case invalidLength
  case invalidEncoding
}

/// The unpadded URL-safe Base64 encoding used by WebAuthn.
///
/// WebAuthn does not permit whitespace, line breaks, or `=` padding. Keeping
/// the decoder strict prevents multiple textual representations of one value.
public enum Base64URL {
  public static func encode(_ data: Data) -> String {
    data.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  public static func decode(_ value: String) throws -> Data {
    guard !value.contains("=") else {
      throw Base64URLError.containsPadding
    }
    guard value.utf8.allSatisfy(isBase64URLByte) else {
      throw Base64URLError.invalidAlphabet
    }

    let remainder = value.utf8.count % 4
    guard remainder != 1 else {
      throw Base64URLError.invalidLength
    }

    var base64 =
      value
      .replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    if remainder != 0 {
      base64.append(String(repeating: "=", count: 4 - remainder))
    }

    guard let decoded = Data(base64Encoded: base64) else {
      throw Base64URLError.invalidEncoding
    }
    return decoded
  }

  private static func isBase64URLByte(_ byte: UInt8) -> Bool {
    switch byte {
    case 48...57, 65...90, 97...122, 45, 95:
      true
    default:
      false
    }
  }
}

extension Data {
  /// Compares secret or unpredictable bytes without returning on the first
  /// mismatch. Length is included in the accumulated difference.
  public func constantTimeEquals(_ other: Data) -> Bool {
    let left = [UInt8](self)
    let right = [UInt8](other)
    let maximumCount = Swift.max(left.count, right.count)
    var difference = left.count ^ right.count

    for index in 0..<maximumCount {
      let leftByte = index < left.count ? left[index] : 0
      let rightByte = index < right.count ? right[index] : 0
      difference |= Int(leftByte ^ rightByte)
    }
    return difference == 0
  }
}
