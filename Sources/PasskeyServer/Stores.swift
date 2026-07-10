import Foundation

public protocol CeremonyStore: Sendable {
  func save(_ state: CeremonyState) async throws
  func consume(id: String, at now: Date) async throws -> CeremonyState
}

public enum CeremonyStoreError: Error, Equatable, Sendable {
  case duplicateID
  case notFound
  case expired
}

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

public protocol PasskeyRepository: Sendable {
  func user(named username: String) async throws -> UserAccount?
  func user(id: UUID) async throws -> UserAccount?
  func credential(id: Data) async throws -> CredentialRecord?
  func credentials(userID: UUID) async throws -> [CredentialRecord]
  func create(user: UserAccount, credential: CredentialRecord) async throws
  func updateAfterAuthentication(
    credentialID: Data,
    signCount: UInt32,
    backupState: Bool,
    usedAt: Date
  ) async throws
}

public enum PasskeyRepositoryError: Error, Equatable, Sendable {
  case usernameAlreadyExists
  case credentialAlreadyExists
  case credentialNotFound
}

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
    precondition(user.id == credential.userID)
    precondition(user.userHandle == credential.userHandle)

    usersByID[user.id] = user
    userIDsByUsername[user.username] = user.id
    credentialsByID[credential.id] = credential
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
