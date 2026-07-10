import Foundation
import Testing

@testable import PasskeyCore

@Suite struct CollectedClientDataTests {
  private let challenge = Data((0..<32).map(UInt8.init))
  private let origin = "https://passkeys.example.com"

  @Test func acceptsExpectedClientData() throws {
    let rawJSON = makeJSON()

    let result = try ClientDataValidator.validate(
      rawJSON,
      expectedType: .create,
      expectedChallenge: challenge,
      allowedOrigins: [origin]
    )

    #expect(result.decoded.origin == origin)
    #expect(result.rawJSON == rawJSON)
  }

  @Test func rejectsChallengeReplayFromAnotherCeremony() {
    #expect(throws: ClientDataValidationError.challengeMismatch) {
      try ClientDataValidator.validate(
        makeJSON(),
        expectedType: .create,
        expectedChallenge: Data(repeating: 0xff, count: 32),
        allowedOrigins: [origin]
      )
    }
  }

  @Test func rejectsWrongOriginTypeAndCrossOrigin() {
    assertFailure(
      makeJSON(origin: "https://evil.example"), .unexpectedOrigin("https://evil.example"))
    assertFailure(
      makeJSON(type: "webauthn.get"),
      .wrongType(expected: "webauthn.create", actual: "webauthn.get"))
    assertFailure(makeJSON(crossOrigin: true), .crossOriginNotAllowed)
  }

  @Test func rejectsPaddedChallenge() {
    let padded = Base64URL.encode(challenge) + "="
    assertFailure(makeJSON(challenge: padded), .malformedChallenge)
  }

  @Test func secureRandomProducesRequestedDistinctValues() throws {
    let first = try SecureRandom.bytes(count: 32)
    let second = try SecureRandom.bytes(count: 32)

    #expect(first.count == 32)
    #expect(second.count == 32)
    #expect(first != second)
  }

  private func assertFailure(
    _ rawJSON: Data,
    _ expectedError: ClientDataValidationError,
    sourceLocation: SourceLocation = #_sourceLocation
  ) {
    #expect(throws: expectedError, sourceLocation: sourceLocation) {
      try ClientDataValidator.validate(
        rawJSON,
        expectedType: .create,
        expectedChallenge: challenge,
        allowedOrigins: [origin]
      )
    }
  }

  private func makeJSON(
    type: String = "webauthn.create",
    challenge: String? = nil,
    origin: String? = nil,
    crossOrigin: Bool = false
  ) -> Data {
    let object: [String: Any] = [
      "type": type,
      "challenge": challenge ?? Base64URL.encode(self.challenge),
      "origin": origin ?? self.origin,
      "crossOrigin": crossOrigin,
    ]
    return try! JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
  }
}
