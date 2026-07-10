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
