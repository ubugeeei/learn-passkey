import Foundation

/// Persistence boundary for single-use ceremony state.
///
/// A distributed implementation must make `consume` an atomic read-and-delete
/// operation so two processes cannot accept the same challenge.
public protocol CeremonyStore: Sendable {
  func save(_ state: CeremonyState) async throws
  func consume(id: String, at now: Date) async throws -> CeremonyState
}

/// Expected ceremony lifecycle failures safe for service-level mapping.
public enum CeremonyStoreError: Error, Equatable, Sendable {
  case duplicateID
  case notFound
  case expired
}

/// Process-local ceremony storage for tests and the hands-on server.
///
/// It is concurrency-safe but intentionally not restart-safe or suitable for a
/// multi-instance deployment.
public actor InMemoryCeremonyStore: CeremonyStore {
  private var states: [String: CeremonyState] = [:]

  public init() {}

  public func save(_ state: CeremonyState) throws {
    guard states[state.id] == nil else {
      throw CeremonyStoreError.duplicateID
    }
    states[state.id] = state
  }

  public func consume(id: String, at now: Date) throws -> CeremonyState {
    guard let state = states.removeValue(forKey: id) else {
      throw CeremonyStoreError.notFound
    }
    guard state.expiresAt > now else {
      throw CeremonyStoreError.expired
    }
    return state
  }

  public var count: Int {
    states.count
  }
}

/// Atomic persistence boundary for accounts and public-key credentials.
public protocol PasskeyRepository: Sendable {
  func user(named username: String) async throws -> UserAccount?
  func user(id: UUID) async throws -> UserAccount?
  func credential(id: Data) async throws -> CredentialRecord?
  func credentials(userID: UUID) async throws -> [CredentialRecord]
  func create(user: UserAccount, credential: CredentialRecord) async throws
  func add(credential: CredentialRecord, to userID: UUID) async throws
  func removeCredential(id: Data, from userID: UUID) async throws
  func updateAfterAuthentication(
    credentialID: Data,
    signCount: UInt32,
    backupState: Bool,
    usedAt: Date
  ) async throws
}

/// Uniqueness and lookup failures raised by a credential repository.
public enum PasskeyRepositoryError: Error, Equatable, Sendable {
  case usernameAlreadyExists
  case credentialAlreadyExists
  case credentialNotFound
  case inconsistentAccountBinding
  case lastCredentialRemovalNotAllowed
}

/// Process-local account and credential storage used by the lab.
///
/// `create(user:credential:)` commits the account and first credential together
/// so a failed registration never leaves a passwordless, unreachable account.
public actor InMemoryPasskeyRepository: PasskeyRepository {
  private var usersByID: [UUID: UserAccount] = [:]
  private var userIDsByUsername: [String: UUID] = [:]
  private var credentialsByID: [Data: CredentialRecord] = [:]

  public init() {}

  public func user(named username: String) -> UserAccount? {
    userIDsByUsername[username].flatMap { usersByID[$0] }
  }

  public func user(id: UUID) -> UserAccount? {
    usersByID[id]
  }

  public func credential(id: Data) -> CredentialRecord? {
    credentialsByID[id]
  }

  public func credentials(userID: UUID) -> [CredentialRecord] {
    credentialsByID.values
      .filter { $0.userID == userID }
      .sorted { $0.createdAt < $1.createdAt }
  }

  public func create(user: UserAccount, credential: CredentialRecord) throws {
    guard userIDsByUsername[user.username] == nil else {
      throw PasskeyRepositoryError.usernameAlreadyExists
    }
    guard credentialsByID[credential.id] == nil else {
      throw PasskeyRepositoryError.credentialAlreadyExists
    }
    guard user.id == credential.userID, user.userHandle == credential.userHandle else {
      throw PasskeyRepositoryError.inconsistentAccountBinding
    }

    usersByID[user.id] = user
    userIDsByUsername[user.username] = user.id
    credentialsByID[credential.id] = credential
  }

  public func add(credential: CredentialRecord, to userID: UUID) throws {
    guard let user = usersByID[userID] else {
      throw PasskeyRepositoryError.credentialNotFound
    }
    guard credential.userID == userID, credential.userHandle == user.userHandle else {
      throw PasskeyRepositoryError.inconsistentAccountBinding
    }
    guard credentialsByID[credential.id] == nil else {
      throw PasskeyRepositoryError.credentialAlreadyExists
    }
    credentialsByID[credential.id] = credential
  }

  public func removeCredential(id: Data, from userID: UUID) throws {
    guard let credential = credentialsByID[id], credential.userID == userID else {
      throw PasskeyRepositoryError.credentialNotFound
    }
    guard credentialsByID.values.count(where: { $0.userID == userID }) > 1 else {
      throw PasskeyRepositoryError.lastCredentialRemovalNotAllowed
    }
    credentialsByID.removeValue(forKey: id)
  }

  public func updateAfterAuthentication(
    credentialID: Data,
    signCount: UInt32,
    backupState: Bool,
    usedAt: Date
  ) throws {
    guard var credential = credentialsByID[credentialID] else {
      throw PasskeyRepositoryError.credentialNotFound
    }
    credential.signCount = signCount
    credential.backupState = backupState
    credential.lastUsedAt = usedAt
    credentialsByID[credentialID] = credential
  }
}
