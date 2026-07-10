import Foundation

public enum SecureRandomError: Error, Equatable, Sendable {
  case invalidCount(Int)
}

public enum SecureRandom {
  public static func bytes(count: Int) throws -> Data {
    guard count > 0 else {
      throw SecureRandomError.invalidCount(count)
    }

    var generator = SystemRandomNumberGenerator()
    return Data((0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
  }
}
