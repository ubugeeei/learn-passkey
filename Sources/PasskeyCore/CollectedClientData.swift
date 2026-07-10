import Foundation

/// Values of `CollectedClientData.type` that separate registration from
/// authentication signatures.
public enum WebAuthnCeremonyType: String, Codable, Sendable {
  case create = "webauthn.create"
  case get = "webauthn.get"
}

/// The client context embedded in `clientDataJSON` by the WebAuthn client.
///
/// The server hashes the original JSON bytes for signature verification; this
/// decoded representation is only for policy checks.
public struct CollectedClientData: Decodable, Equatable, Sendable {
  public let type: String
  public let challenge: String
  public let origin: String
  public let crossOrigin: Bool?
  public let topOrigin: String?

  public init(
    type: String,
    challenge: String,
    origin: String,
    crossOrigin: Bool? = nil,
    topOrigin: String? = nil
  ) {
    self.type = type
    self.challenge = challenge
    self.origin = origin
    self.crossOrigin = crossOrigin
    self.topOrigin = topOrigin
  }
}

/// A precise reason why client data failed an RP binding check.
public enum ClientDataValidationError: Error, Equatable, Sendable {
  case tooLarge(actual: Int, maximum: Int)
  case malformedJSON
  case wrongType(expected: String, actual: String)
  case malformedChallenge
  case challengeMismatch
  case unexpectedOrigin(String)
  case crossOriginNotAllowed
  case topOriginNotAllowed
}

/// Validated fields paired with the untouched bytes used by the signature.
public struct ValidatedClientData: Sendable {
  public let decoded: CollectedClientData
  public let rawJSON: Data

  public init(decoded: CollectedClientData, rawJSON: Data) {
    self.decoded = decoded
    self.rawJSON = rawJSON
  }
}

/// Applies ceremony type, challenge, origin, and cross-origin policy checks to
/// `clientDataJSON` before any credential is accepted.
public enum ClientDataValidator {
  public static let defaultMaximumByteCount = 8 * 1024

  /// Validates client data against server-held expectations.
  ///
  /// - Important: `expectedChallenge` must come from a consumed, single-use
  ///   ceremony record. Values echoed from the request are not expectations.
  public static func validate(
    _ rawJSON: Data,
    expectedType: WebAuthnCeremonyType,
    expectedChallenge: Data,
    allowedOrigins: Set<String>,
    maximumByteCount: Int = defaultMaximumByteCount
  ) throws -> ValidatedClientData {
    guard rawJSON.count <= maximumByteCount else {
      throw ClientDataValidationError.tooLarge(
        actual: rawJSON.count,
        maximum: maximumByteCount
      )
    }

    let clientData: CollectedClientData
    do {
      clientData = try JSONDecoder().decode(CollectedClientData.self, from: rawJSON)
    } catch {
      throw ClientDataValidationError.malformedJSON
    }

    guard clientData.type == expectedType.rawValue else {
      throw ClientDataValidationError.wrongType(
        expected: expectedType.rawValue,
        actual: clientData.type
      )
    }

    let receivedChallenge: Data
    do {
      receivedChallenge = try Base64URL.decode(clientData.challenge)
    } catch {
      throw ClientDataValidationError.malformedChallenge
    }
    guard receivedChallenge.constantTimeEquals(expectedChallenge) else {
      throw ClientDataValidationError.challengeMismatch
    }

    guard allowedOrigins.contains(clientData.origin) else {
      throw ClientDataValidationError.unexpectedOrigin(clientData.origin)
    }
    guard clientData.crossOrigin != true else {
      throw ClientDataValidationError.crossOriginNotAllowed
    }
    guard clientData.topOrigin == nil else {
      throw ClientDataValidationError.topOriginNotAllowed
    }

    return ValidatedClientData(decoded: clientData, rawJSON: rawJSON)
  }
}
