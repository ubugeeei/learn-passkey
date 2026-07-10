import Foundation
import PasskeyCore
import Testing

@testable import PasskeyServer

@Suite struct CeremonyAndOptionsTests {
  private let now = Date(timeIntervalSince1970: 1_800_000_000)

  @Test func issuesRegistrationOptionsAndKeepsAccountPending() async throws {
    let repository = InMemoryPasskeyRepository()
    let ceremonies = InMemoryCeremonyStore()
    let service = try makeService(repository: repository, ceremonies: ceremonies)

    let response = try await service.beginRegistration(
      username: "alice@example.com",
      displayName: "Alice"
    )

    #expect(response.publicKey.rp.id == "passkeys.example.com")
    #expect(response.publicKey.pubKeyCredParams == [.init(alg: -7)])
    #expect(response.publicKey.authenticatorSelection.residentKey == .required)
    #expect(response.publicKey.authenticatorSelection.userVerification == .required)
    #expect(response.publicKey.attestation == .none)
    #expect(try Base64URL.decode(response.publicKey.user.id).count == 32)
    #expect(try Base64URL.decode(response.publicKey.challenge).count == 32)
    #expect(await repository.user(named: "alice@example.com") == nil)
    #expect(await ceremonies.count == 1)
  }

  @Test func consumesCeremonyExactlyOnceAndRejectsExpiry() async throws {
    let store = InMemoryCeremonyStore()
    let state = CeremonyState(
      id: "one-time",
      challenge: Data(repeating: 1, count: 32),
      purpose: .authentication(expectedUserID: nil, requireUserHandle: true),
      expiresAt: now.addingTimeInterval(60)
    )
    try await store.save(state)

    #expect(try await store.consume(id: state.id, at: now) == state)
    await #expect(throws: CeremonyStoreError.notFound) {
      try await store.consume(id: state.id, at: now)
    }

    let expired = CeremonyState(
      id: "expired",
      challenge: state.challenge,
      purpose: state.purpose,
      expiresAt: now
    )
    try await store.save(expired)
    await #expect(throws: CeremonyStoreError.expired) {
      try await store.consume(id: expired.id, at: now)
    }
    #expect(await store.count == 0)
  }

  @Test func usernameLessAuthenticationDoesNotLeakAccountLookup() async throws {
    let service = try makeService()

    let response = try await service.beginAuthentication()

    #expect(response.publicKey.allowCredentials.isEmpty)
    #expect(response.publicKey.rpId == "passkeys.example.com")
    #expect(try Base64URL.decode(response.publicKey.challenge).count == 32)
  }

  @Test func validatesRelyingPartyBoundaries() {
    #expect(throws: RelyingPartyConfigurationError.invalidRPID("https://example.com")) {
      try RelyingPartyConfiguration(
        id: "https://example.com",
        name: "Bad",
        allowedOrigins: ["https://example.com"]
      )
    }
    #expect(throws: RelyingPartyConfigurationError.invalidOrigin("https://evil.example")) {
      try RelyingPartyConfiguration(
        id: "example.com",
        name: "Bad",
        allowedOrigins: ["https://evil.example"]
      )
    }
  }

  private func makeService(
    repository: InMemoryPasskeyRepository = InMemoryPasskeyRepository(),
    ceremonies: InMemoryCeremonyStore = InMemoryCeremonyStore()
  ) throws -> PasskeyService {
    let configuration = try RelyingPartyConfiguration(
      id: "passkeys.example.com",
      name: "Passkey Lab",
      allowedOrigins: ["https://passkeys.example.com"]
    )
    let bytes: @Sendable (Int) throws -> Data = { count in
      Data((0..<count).map { UInt8($0 & 0xff) })
    }
    return PasskeyService(
      configuration: configuration,
      repository: repository,
      ceremonies: ceremonies,
      now: { now },
      randomBytes: bytes
    )
  }
}
