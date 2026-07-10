import Foundation

/// Invalid requests made to `SecureRandom`.
public enum SecureRandomError: Error, Equatable, Sendable {
  case invalidCount(Int)
}

/// Generates unpredictable bytes with Swift's system cryptographic RNG.
public enum SecureRandom {
  /// Returns exactly `count` random bytes, rejecting zero or negative counts.
  public static func bytes(count: Int) throws -> Data {
    guard count > 0 else {
      throw SecureRandomError.invalidCount(count)
    }

    var generator = SystemRandomNumberGenerator()
    return Data((0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
  }
}
