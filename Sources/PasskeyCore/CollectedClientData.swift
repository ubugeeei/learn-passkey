import Foundation

public enum WebAuthnCeremonyType: String, Codable, Sendable {
  case create = "webauthn.create"
  case get = "webauthn.get"
}

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

public struct ValidatedClientData: Sendable {
  public let decoded: CollectedClientData
  public let rawJSON: Data

  public init(decoded: CollectedClientData, rawJSON: Data) {
    self.decoded = decoded
    self.rawJSON = rawJSON
  }
}

public enum ClientDataValidator {
  public static let defaultMaximumByteCount = 8 * 1024

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
