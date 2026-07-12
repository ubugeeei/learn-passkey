import Crypto
import Foundation
import PasskeyCore
import Testing

@testable import PasskeyServer

@Suite struct CeremonyVerificationTests {
  @Test func completesRegistrationAndAuthenticationEndToEnd() async throws {
    let repository = InMemoryPasskeyRepository()
    let service = try makeService(repository: repository)
    let authenticator = TestAuthenticator()

    let registration = try await register(authenticator, with: service)
    let authenticationOptions = try await service.beginAuthentication()
    let authenticationRequest = try authenticator.authenticationRequest(
      options: authenticationOptions,
      userHandle: Base64URL.encode(registration.user.userHandle),
      signCount: 1
    )
    let result = try await service.completeAuthentication(authenticationRequest)

    #expect(result.user.username == "alice@example.com")
    #expect(result.credential.id == authenticator.credentialID)
    #expect(result.credential.signCount == 1)
    #expect(result.credential.lastUsedAt != nil)
  }

  @Test func rejectsWrongOriginAndConsumesChallenge() async throws {
    let service = try makeService()
    let authenticator = TestAuthenticator()
    let options = try await service.beginRegistration(
      username: "alice@example.com",
      displayName: "Alice"
    )
    let request = try authenticator.registrationRequest(
      options: options,
      origin: "https://evil.example"
    )

    await #expect(
      throws: RegistrationVerificationError.clientData(
        .unexpectedOrigin("https://evil.example")
      )
    ) {
      try await service.completeRegistration(request)
    }
    await #expect(throws: CeremonyStoreError.notFound) {
      try await service.completeRegistration(request)
    }
  }

  @Test func rejectsMissingUserVerificationAndWrongRPID() async throws {
    let authenticator = TestAuthenticator()

    let serviceWithoutUV = try makeService()
    let optionsWithoutUV = try await serviceWithoutUV.beginRegistration(
      username: "alice@example.com",
      displayName: "Alice"
    )
    let requestWithoutUV = try authenticator.registrationRequest(
      options: optionsWithoutUV,
      includeUserVerification: false
    )
    await #expect(throws: RegistrationVerificationError.userVerificationRequired) {
      try await serviceWithoutUV.completeRegistration(requestWithoutUV)
    }

    let serviceWithWrongRP = try makeService()
    let optionsWithWrongRP = try await serviceWithWrongRP.beginRegistration(
      username: "bob@example.com",
      displayName: "Bob"
    )
    let requestWithWrongRP = try authenticator.registrationRequest(
      options: optionsWithWrongRP,
      rpID: "other.example.com"
    )
    await #expect(throws: RegistrationVerificationError.rpIDHashMismatch) {
      try await serviceWithWrongRP.completeRegistration(requestWithWrongRP)
    }
  }

  @Test func rejectsSignatureFromAnotherPrivateKey() async throws {
    let service = try makeService()
    let authenticator = TestAuthenticator()
    let registration = try await register(authenticator, with: service)
    let options = try await service.beginAuthentication()
    let request = try authenticator.authenticationRequest(
      options: options,
      userHandle: Base64URL.encode(registration.user.userHandle),
      signCount: 1,
      signingKey: P256.Signing.PrivateKey()
    )

    await #expect(throws: AuthenticationVerificationError.invalidSignature) {
      try await service.completeAuthentication(request)
    }
  }

  @Test func rejectsCoordinatesThatAreNotAPointOnP256() async throws {
    let service = try makeService()
    let authenticator = TestAuthenticator()
    let options = try await service.beginRegistration(
      username: "alice@example.com",
      displayName: "Alice"
    )
    let request = try authenticator.registrationRequest(
      options: options,
      publicKeyX963: Data([0x04]) + Data(repeating: 0, count: 64)
    )

    await #expect(throws: RegistrationVerificationError.invalidPublicKey) {
      try await service.completeRegistration(request)
    }
  }

  @Test(
    "Registration rejects each independently invalid protocol binding",
    arguments: RegistrationRejection.examples
  )
  func rejectsInvalidRegistrationBinding(example: RegistrationRejection) async throws {
    let service = try makeService()
    let authenticator = TestAuthenticator()
    let options = try await service.beginRegistration(
      username: "alice@example.com",
      displayName: "Alice"
    )
    let request = try example.makeRequest(authenticator, options)

    await #expect(throws: example.expectedError) {
      try await service.completeRegistration(request)
    }
  }

  @Test func rejectsMissingAndMismatchedDiscoverableUserHandles() async throws {
    let authenticator = TestAuthenticator()

    for userHandle in [nil, Base64URL.encode(Data(repeating: 0xff, count: 32))] {
      let service = try makeService()
      _ = try await register(authenticator, with: service)
      let options = try await service.beginAuthentication()
      let request = try authenticator.authenticationRequest(
        options: options,
        userHandle: userHandle,
        signCount: 1
      )

      if userHandle == nil {
        await #expect(throws: AuthenticationVerificationError.userHandleRequired) {
          try await service.completeAuthentication(request)
        }
      } else {
        await #expect(throws: AuthenticationVerificationError.userHandleMismatch) {
          try await service.completeAuthentication(request)
        }
      }
    }
  }

  @Test(
    "Authentication rejects each independently invalid RP binding",
    arguments: AuthenticationRejection.examples
  )
  func rejectsInvalidAuthenticationBinding(example: AuthenticationRejection) async throws {
    let service = try makeService()
    let authenticator = TestAuthenticator()
    let registration = try await register(authenticator, with: service)
    let options = try await service.beginAuthentication()
    let request = try authenticator.authenticationRequest(
      options: options,
      userHandle: Base64URL.encode(registration.user.userHandle),
      signCount: 1,
      origin: example.origin,
      rpID: example.rpID,
      ceremonyType: example.ceremonyType,
      includeUserPresence: example.includeUserPresence,
      includeUserVerification: example.includeUserVerification
    )

    await #expect(throws: example.expectedError) {
      try await service.completeAuthentication(request)
    }
  }

  @Test func rejectsChangedBackupEligibility() async throws {
    let service = try makeService()
    let authenticator = TestAuthenticator()
    let registrationOptions = try await service.beginRegistration(
      username: "alice@example.com",
      displayName: "Alice"
    )
    _ = try await service.completeRegistration(
      authenticator.registrationRequest(options: registrationOptions, backupEligible: true)
    )
    let options = try await service.beginAuthentication()
    let request = try authenticator.authenticationRequest(
      options: options,
      userHandle: nil,
      signCount: 1,
      backupEligible: false
    )

    await #expect(throws: AuthenticationVerificationError.backupEligibilityChanged) {
      try await service.completeAuthentication(request)
    }
  }

  @Test(
    "Registration credential IDs enforce both length boundaries",
    arguments: [0, 1_025]
  )
  func rejectsInvalidRegistrationCredentialIDLength(length: Int) {
    #expect(throws: RegistrationVerificationError.invalidCredentialIDLength(length)) {
      try RegistrationVerifier.verify(
        RegistrationVerificationInput(
          credentialID: Data(repeating: 0, count: length),
          clientDataJSON: Data(),
          attestationObject: Data()
        ),
        expecting: RegistrationExpectation(
          challenge: Data(repeating: 0, count: 32),
          rpID: "passkeys.example.com",
          allowedOrigins: ["https://passkeys.example.com"],
          requireUserVerification: true
        )
      )
    }
  }

  @Test func rejectsWrongCeremonyPurposeBeforeParsingCredentialBytes() async throws {
    let service = try makeService()
    let registration = try await service.beginRegistration(
      username: "alice@example.com",
      displayName: "Alice"
    )
    let request = CompleteAuthenticationRequest(
      ceremonyID: registration.ceremonyID,
      id: "",
      rawId: "",
      type: .publicKey,
      response: AuthenticationCredentialResponse(
        clientDataJSON: "",
        authenticatorData: "",
        signature: "",
        userHandle: nil
      )
    )

    await #expect(throws: PasskeyServiceError.wrongCeremonyType) {
      try await service.completeAuthentication(request)
    }
  }

  @Test func acceptsTheDocumentedZeroCounterPolicyAcrossSignIns() async throws {
    let service = try makeService()
    let authenticator = TestAuthenticator()
    let registration = try await register(authenticator, with: service)
    let userHandle = Base64URL.encode(registration.user.userHandle)

    for _ in 0..<2 {
      let options = try await service.beginAuthentication()
      let request = try authenticator.authenticationRequest(
        options: options,
        userHandle: userHandle,
        signCount: 0
      )
      let result = try await service.completeAuthentication(request)
      #expect(result.credential.signCount == 0)
    }
  }

  @Test func rejectsMalformedDERSignatureAfterAllBindingsPass() async throws {
    let service = try makeService()
    let authenticator = TestAuthenticator()
    let registration = try await register(authenticator, with: service)
    let options = try await service.beginAuthentication()
    let valid = try authenticator.authenticationRequest(
      options: options,
      userHandle: Base64URL.encode(registration.user.userHandle),
      signCount: 1
    )
    let malformed = CompleteAuthenticationRequest(
      ceremonyID: valid.ceremonyID,
      id: valid.id,
      rawId: valid.rawId,
      type: valid.type,
      response: AuthenticationCredentialResponse(
        clientDataJSON: valid.response.clientDataJSON,
        authenticatorData: valid.response.authenticatorData,
        signature: Base64URL.encode(Data([0x30, 0x00])),
        userHandle: valid.response.userHandle
      )
    )

    await #expect(throws: AuthenticationVerificationError.malformedPublicKeyOrSignature) {
      try await service.completeAuthentication(malformed)
    }
  }

  @Test func rejectsAValidSignatureWhenCounterDoesNotAdvance() async throws {
    let service = try makeService()
    let authenticator = TestAuthenticator()
    let registration = try await register(authenticator, with: service)
    let userHandle = Base64URL.encode(registration.user.userHandle)

    let firstOptions = try await service.beginAuthentication()
    let firstRequest = try authenticator.authenticationRequest(
      options: firstOptions,
      userHandle: userHandle,
      signCount: 1
    )
    _ = try await service.completeAuthentication(firstRequest)

    let replayOptions = try await service.beginAuthentication()
    let replayRequest = try authenticator.authenticationRequest(
      options: replayOptions,
      userHandle: userHandle,
      signCount: 1
    )
    await #expect(
      throws: AuthenticationVerificationError.signatureCounterDidNotAdvance(
        stored: 1,
        received: 1
      )
    ) {
      try await service.completeAuthentication(replayRequest)
    }
  }

  private func register(
    _ authenticator: TestAuthenticator,
    with service: PasskeyService
  ) async throws -> RegistrationCompletionResult {
    let options = try await service.beginRegistration(
      username: "alice@example.com",
      displayName: "Alice"
    )
    return try await service.completeRegistration(
      authenticator.registrationRequest(options: options)
    )
  }

  private func makeService(
    repository: InMemoryPasskeyRepository = InMemoryPasskeyRepository()
  ) throws -> PasskeyService {
    let configuration = try RelyingPartyConfiguration(
      id: "passkeys.example.com",
      name: "Passkey Lab",
      allowedOrigins: ["https://passkeys.example.com"]
    )
    return PasskeyService(
      configuration: configuration,
      repository: repository,
      ceremonies: InMemoryCeremonyStore(),
      now: { Date(timeIntervalSince1970: 1_800_000_000) }
    )
  }
}

struct RegistrationRejection: CustomTestStringConvertible, Sendable {
  typealias RequestFactory = @Sendable (TestAuthenticator, RegistrationOptionsResponse) throws ->
    CompleteRegistrationRequest

  let name: String
  let expectedError: RegistrationVerificationError
  let makeRequest: RequestFactory

  var testDescription: String { name }

  static let examples = [
    RegistrationRejection(
      name: "wrong ceremony type",
      expectedError: .clientData(
        .wrongType(expected: "webauthn.create", actual: "webauthn.get")
      )
    ) {
      try $0.registrationRequest(options: $1, ceremonyType: "webauthn.get")
    },
    RegistrationRejection(name: "missing user presence", expectedError: .userPresenceRequired) {
      try $0.registrationRequest(options: $1, includeUserPresence: false)
    },
    RegistrationRejection(
      name: "embedded credential ID differs", expectedError: .credentialIDMismatch
    ) {
      try $0.registrationRequest(options: $1, embeddedCredentialID: Data([0x01]))
    },
    RegistrationRejection(
      name: "unsupported attestation format", expectedError: .unsupportedAttestationFormat("packed")
    ) {
      try $0.registrationRequest(options: $1, attestationFormat: "packed")
    },
    RegistrationRejection(
      name: "none attestation has a statement", expectedError: .nonEmptyNoneAttestationStatement
    ) {
      try $0.registrationRequest(
        options: $1,
        attestationStatement: [(.text("unexpected"), .unsigned(1))]
      )
    },
  ]
}

struct AuthenticationRejection: CustomTestStringConvertible, Sendable {
  let name: String
  let origin: String
  let rpID: String
  let ceremonyType: String
  let includeUserPresence: Bool
  let includeUserVerification: Bool
  let expectedError: AuthenticationVerificationError

  var testDescription: String { name }

  static let examples = [
    AuthenticationRejection(
      name: "wrong origin",
      origin: "https://evil.example",
      rpID: "passkeys.example.com",
      ceremonyType: "webauthn.get",
      includeUserPresence: true,
      includeUserVerification: true,
      expectedError: .clientData(.unexpectedOrigin("https://evil.example"))
    ),
    AuthenticationRejection(
      name: "wrong RP ID",
      origin: "https://passkeys.example.com",
      rpID: "other.example.com",
      ceremonyType: "webauthn.get",
      includeUserPresence: true,
      includeUserVerification: true,
      expectedError: .rpIDHashMismatch
    ),
    AuthenticationRejection(
      name: "wrong ceremony type",
      origin: "https://passkeys.example.com",
      rpID: "passkeys.example.com",
      ceremonyType: "webauthn.create",
      includeUserPresence: true,
      includeUserVerification: true,
      expectedError: .clientData(
        .wrongType(expected: "webauthn.get", actual: "webauthn.create")
      )
    ),
    AuthenticationRejection(
      name: "missing user presence",
      origin: "https://passkeys.example.com",
      rpID: "passkeys.example.com",
      ceremonyType: "webauthn.get",
      includeUserPresence: false,
      includeUserVerification: true,
      expectedError: .userPresenceRequired
    ),
    AuthenticationRejection(
      name: "missing user verification",
      origin: "https://passkeys.example.com",
      rpID: "passkeys.example.com",
      ceremonyType: "webauthn.get",
      includeUserPresence: true,
      includeUserVerification: false,
      expectedError: .userVerificationRequired
    ),
  ]
}
