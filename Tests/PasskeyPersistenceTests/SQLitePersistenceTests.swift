import Crypto
import Foundation
import PasskeyCore
import PasskeyServer
import Testing

@testable import PasskeyPersistence

@Suite struct SQLitePersistenceTests {
  @Test func accountAndCredentialSurviveReopeningDatabase() async throws {
    let database = TemporaryDatabase()
    let user = makeUser()
    let credential = try makeCredential(user: user)
    do {
      let repository = try SQLitePasskeyRepository(path: database.path)
      try await repository.create(user: user, credential: credential)
    }

    let reopened = try SQLitePasskeyRepository(path: database.path)

    #expect(try await reopened.user(named: user.username) == user)
    #expect(try await reopened.credential(id: credential.id) == credential)
  }

  @Test func duplicateUsernameRollsBackTheSecondAccount() async throws {
    let database = TemporaryDatabase()
    let repository = try SQLitePasskeyRepository(path: database.path)
    let first = makeUser()
    try await repository.create(user: first, credential: makeCredential(user: first))
    let second = UserAccount(
      id: UUID(),
      userHandle: Data(repeating: 0x55, count: 32),
      username: first.username,
      displayName: "Other Alice",
      createdAt: first.createdAt
    )

    await #expect(throws: PasskeyRepositoryError.usernameAlreadyExists) {
      try await repository.create(
        user: second,
        credential: self.makeCredential(user: second, idByte: 0x66)
      )
    }

    #expect(try await repository.user(id: second.id) == nil)
    #expect(try await repository.credentials(userID: second.id).isEmpty)
  }

  @Test func authenticationMetadataUpdateIsDurable() async throws {
    let database = TemporaryDatabase()
    let repository = try SQLitePasskeyRepository(path: database.path)
    let user = makeUser()
    let credential = try makeCredential(user: user)
    try await repository.create(user: user, credential: credential)
    let usedAt = user.createdAt.addingTimeInterval(60)

    try await repository.updateAfterAuthentication(
      credentialID: credential.id,
      signCount: 9,
      backupState: false,
      usedAt: usedAt
    )

    let reopened = try SQLitePasskeyRepository(path: database.path)
    let updated = try #require(try await reopened.credential(id: credential.id))
    #expect(updated.signCount == 9)
    #expect(updated.lastUsedAt == usedAt)
  }

  @Test func twoConnectionsCanConsumeCeremonyOnlyOnce() async throws {
    let database = TemporaryDatabase()
    let first = try SQLiteCeremonyStore(path: database.path)
    let second = try SQLiteCeremonyStore(path: database.path)
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    let state = CeremonyState(
      id: "atomic-ceremony",
      challenge: Data(repeating: 0x77, count: 32),
      purpose: .authentication(expectedUserID: nil, requireUserHandle: true),
      expiresAt: now.addingTimeInterval(60)
    )
    try await first.save(state)

    let successes = await withTaskGroup(of: Bool.self) { group in
      group.addTask { (try? await first.consume(id: state.id, at: now)) != nil }
      group.addTask { (try? await second.consume(id: state.id, at: now)) != nil }
      var results: [Bool] = []
      for await result in group { results.append(result) }
      return results.filter { $0 }.count
    }

    #expect(successes == 1)
  }

  @Test func pendingRegistrationCeremonySurvivesReopening() async throws {
    let database = TemporaryDatabase()
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    let state = CeremonyState(
      id: "pending-registration",
      challenge: Data(repeating: 0x88, count: 32),
      purpose: .registration(PendingRegistration(user: makeUser())),
      expiresAt: now.addingTimeInterval(60)
    )
    try await SQLiteCeremonyStore(path: database.path).save(state)

    let reopened = try SQLiteCeremonyStore(path: database.path)

    #expect(try await reopened.consume(id: state.id, at: now) == state)
  }

  @Test func hashedSessionSurvivesReopeningAndCanBeRevoked() async throws {
    let database = TemporaryDatabase()
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    let userID = UUID()
    let issuer = try SessionManager(
      store: SQLiteSessionStore(path: database.path),
      timeToLive: 3_600,
      now: { now },
      randomBytes: { Data(repeating: 0x99, count: $0) }
    )
    let issued = try await issuer.issue(userID: userID)
    let reopened = try SessionManager(
      store: SQLiteSessionStore(path: database.path),
      timeToLive: 3_600,
      now: { now }
    )

    #expect(try await reopened.authenticate(token: issued.token) == userID)
    try await reopened.revoke(token: issued.token)
    await #expect(throws: SessionManagerError.invalidSession) {
      try await reopened.authenticate(token: issued.token)
    }
  }

  private func makeUser() -> UserAccount {
    UserAccount(
      id: UUID(uuidString: "EB1E1AE6-D948-4BE4-9CC9-F379487FF2BB")!,
      userHandle: Data(repeating: 0x11, count: 32),
      username: "alice@example.com",
      displayName: "Alice",
      createdAt: Date(timeIntervalSince1970: 1_800_000_000)
    )
  }

  private func makeCredential(
    user: UserAccount,
    idByte: UInt8 = 0x22
  ) throws -> CredentialRecord {
    let publicKey = P256.Signing.PrivateKey().publicKey.x963Representation
    return try CredentialRecord(
      id: Data(repeating: idByte, count: 32),
      userID: user.id,
      userHandle: user.userHandle,
      publicKey: COSEEC2PublicKey(
        algorithm: -7,
        curve: 1,
        x: publicKey.subdata(in: 1..<33),
        y: publicKey.subdata(in: 33..<65)
      ),
      rawPublicKey: Data([0xa0]),
      aaguid: Data(repeating: 0, count: 16),
      signCount: 0,
      backupEligible: false,
      backupState: false,
      createdAt: user.createdAt
    )
  }
}

private final class TemporaryDatabase: @unchecked Sendable {
  let path: String

  init() {
    path =
      FileManager.default.temporaryDirectory
      .appendingPathComponent("learn-passkey-\(UUID().uuidString).sqlite")
      .path
  }

  deinit {
    for suffix in ["", "-shm", "-wal"] {
      try? FileManager.default.removeItem(atPath: path + suffix)
    }
  }
}
