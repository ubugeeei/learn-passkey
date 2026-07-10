import Foundation
import PasskeyCore

/// Immutable RP policy shared by option generation and response verification.
///
/// Construction rejects origins that are not exact HTTPS origins whose hosts
/// equal or are subdomains of the RP ID. Validating configuration once prevents
/// individual ceremony code paths from drifting apart.
public struct RelyingPartyConfiguration: Equatable, Sendable {
  public let id: String
  public let name: String
  public let allowedOrigins: Set<String>
  public let ceremonyTimeToLive: TimeInterval
  public let requestTimeoutMilliseconds: Int
  public let userVerification: UserVerificationRequirement

  public init(
    id: String,
    name: String,
    allowedOrigins: Set<String>,
    ceremonyTimeToLive: TimeInterval = 5 * 60,
    requestTimeoutMilliseconds: Int = 5 * 60 * 1_000,
    userVerification: UserVerificationRequirement = .required
  ) throws {
    guard Self.isValidRPID(id) else {
      throw RelyingPartyConfigurationError.invalidRPID(id)
    }
    guard !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
      throw RelyingPartyConfigurationError.emptyName
    }
    guard !allowedOrigins.isEmpty else {
      throw RelyingPartyConfigurationError.noAllowedOrigins
    }
    for origin in allowedOrigins {
      guard Self.isValidOrigin(origin, rpID: id) else {
        throw RelyingPartyConfigurationError.invalidOrigin(origin)
      }
    }
    guard ceremonyTimeToLive > 0 else {
      throw RelyingPartyConfigurationError.invalidCeremonyTimeToLive
    }
    guard requestTimeoutMilliseconds > 0 else {
      throw RelyingPartyConfigurationError.invalidRequestTimeout
    }

    self.id = id
    self.name = name
    self.allowedOrigins = allowedOrigins
    self.ceremonyTimeToLive = ceremonyTimeToLive
    self.requestTimeoutMilliseconds = requestTimeoutMilliseconds
    self.userVerification = userVerification
  }

  private static func isValidRPID(_ value: String) -> Bool {
    guard value == value.lowercased(),
      !value.isEmpty,
      !value.hasPrefix("."),
      !value.hasSuffix("."),
      !value.contains("..")
    else {
      return false
    }
    return value.utf8.allSatisfy { byte in
      (97...122).contains(byte) || (48...57).contains(byte) || byte == 45 || byte == 46
    }
  }

  private static func isValidOrigin(_ value: String, rpID: String) -> Bool {
    guard let components = URLComponents(string: value),
      components.scheme == "https",
      let host = components.host?.lowercased(),
      components.user == nil,
      components.password == nil,
      components.query == nil,
      components.fragment == nil,
      components.path.isEmpty,
      host == rpID || host.hasSuffix(".\(rpID)")
    else {
      return false
    }
    return components.string == value
  }
}

/// A startup-time relying-party configuration error.
public enum RelyingPartyConfigurationError: Error, Equatable, Sendable {
  case invalidRPID(String)
  case emptyName
  case noAllowedOrigins
  case invalidOrigin(String)
  case invalidCeremonyTimeToLive
  case invalidRequestTimeout
}
