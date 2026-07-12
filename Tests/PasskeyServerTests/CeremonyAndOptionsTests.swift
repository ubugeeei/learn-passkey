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

  @Test func repositoryRejectsInconsistentAccountBindingWithoutPartialWrite() async throws {
    let repository = InMemoryPasskeyRepository()
    let user = UserAccount(
      id: UUID(),
      userHandle: Data(repeating: 0x01, count: 32),
      username: "alice@example.com",
      displayName: "Alice",
      createdAt: now
    )
    let otherUserID = UUID()
    let credential = try CredentialRecord(
      id: Data(repeating: 0x02, count: 32),
      userID: otherUserID,
      userHandle: user.userHandle,
      publicKey: COSEEC2PublicKey(
        algorithm: -7,
        curve: 1,
        x: Data(repeating: 0x03, count: 32),
        y: Data(repeating: 0x04, count: 32)
      ),
      rawPublicKey: Data(),
      aaguid: Data(repeating: 0, count: 16),
      signCount: 0,
      backupEligible: false,
      backupState: false,
      createdAt: now
    )

    await #expect(throws: PasskeyRepositoryError.inconsistentAccountBinding) {
      try await repository.create(user: user, credential: credential)
    }
    #expect(await repository.user(id: user.id) == nil)
    #expect(await repository.credential(id: credential.id) == nil)
  }

  @Test(
    "Registration rejects empty and oversized account labels",
    arguments: InvalidAccountLabel.examples
  )
  func rejectsInvalidAccountLabels(example: InvalidAccountLabel) async throws {
    let service = try makeService()

    await #expect(throws: example.expectedError) {
      try await service.beginRegistration(
        username: example.username,
        displayName: example.displayName
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

struct InvalidAccountLabel: CustomTestStringConvertible, Sendable {
  let name: String
  let username: String
  let displayName: String
  let expectedError: PasskeyServiceError

  var testDescription: String { name }

  static let examples = [
    InvalidAccountLabel(
      name: "blank username",
      username: " \n ",
      displayName: "Alice",
      expectedError: .invalidUsername
    ),
    InvalidAccountLabel(
      name: "username over 128 UTF-8 bytes",
      username: String(repeating: "a", count: 129),
      displayName: "Alice",
      expectedError: .invalidUsername
    ),
    InvalidAccountLabel(
      name: "blank display name",
      username: "alice@example.com",
      displayName: "\t",
      expectedError: .invalidDisplayName
    ),
    InvalidAccountLabel(
      name: "display name over 128 UTF-8 bytes",
      username: "alice@example.com",
      displayName: String(repeating: "é", count: 65),
      expectedError: .invalidDisplayName
    ),
  ]
}
