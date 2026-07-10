import Foundation
import PasskeyCore

public struct SessionRecord: Equatable, Sendable {
  public let tokenHash: Data
  public let userID: UUID
  public let createdAt: Date
  public let expiresAt: Date

  public init(tokenHash: Data, userID: UUID, createdAt: Date, expiresAt: Date) {
    self.tokenHash = tokenHash
    self.userID = userID
    self.createdAt = createdAt
    self.expiresAt = expiresAt
  }
}

public struct IssuedSession: Equatable, Sendable {
  public let token: String
  public let userID: UUID
  public let expiresAt: Date

  public init(token: String, userID: UUID, expiresAt: Date) {
    self.token = token
    self.userID = userID
    self.expiresAt = expiresAt
  }
}

public protocol SessionStore: Sendable {
  func save(_ session: SessionRecord) async throws
  func find(tokenHash: Data, at now: Date) async throws -> SessionRecord?
  func delete(tokenHash: Data) async throws
  func deleteAll(userID: UUID) async throws
}

public enum SessionStoreError: Error, Equatable, Sendable {
  case duplicateTokenHash
}

public actor InMemorySessionStore: SessionStore {
  private var records: [Data: SessionRecord] = [:]

  public init() {}

  public func save(_ session: SessionRecord) throws {
    guard records[session.tokenHash] == nil else {
      throw SessionStoreError.duplicateTokenHash
    }
    records[session.tokenHash] = session
  }

  public func find(tokenHash: Data, at now: Date) -> SessionRecord? {
    guard let record = records[tokenHash] else { return nil }
    guard record.expiresAt > now else {
      records.removeValue(forKey: tokenHash)
      return nil
    }
    return record
  }

  public func delete(tokenHash: Data) {
    records.removeValue(forKey: tokenHash)
  }

  public func deleteAll(userID: UUID) {
    records = records.filter { $0.value.userID != userID }
  }

  public var count: Int {
    records.count
  }
}

public final class SessionManager: Sendable {
  public let store: any SessionStore
  public let timeToLive: TimeInterval

  private let now: @Sendable () -> Date
  private let randomBytes: @Sendable (Int) throws -> Data

  public init(
    store: any SessionStore,
    timeToLive: TimeInterval = 8 * 60 * 60,
    now: @escaping @Sendable () -> Date = { Date() },
    randomBytes: @escaping @Sendable (Int) throws -> Data = { try SecureRandom.bytes(count: $0) }
  ) throws {
    guard timeToLive > 0 else {
      throw SessionManagerError.invalidTimeToLive
    }
    self.store = store
    self.timeToLive = timeToLive
    self.now = now
    self.randomBytes = randomBytes
  }

  public func issue(userID: UUID) async throws -> IssuedSession {
    let rawToken = try randomBytes(32)
    let issuedAt = now()
    let expiresAt = issuedAt.addingTimeInterval(timeToLive)
    try await store.save(
      SessionRecord(
        tokenHash: WebAuthnCrypto.sha256(rawToken),
        userID: userID,
        createdAt: issuedAt,
        expiresAt: expiresAt
      )
    )
    return IssuedSession(
      token: Base64URL.encode(rawToken),
      userID: userID,
      expiresAt: expiresAt
    )
  }

  public func authenticate(token: String) async throws -> UUID {
    let rawToken: Data
    do {
      rawToken = try Base64URL.decode(token)
    } catch {
      throw SessionManagerError.invalidSession
    }
    guard rawToken.count == 32,
      let session = try await store.find(
        tokenHash: WebAuthnCrypto.sha256(rawToken),
        at: now()
      )
    else {
      throw SessionManagerError.invalidSession
    }
    return session.userID
  }

  public func revoke(token: String) async throws {
    let rawToken: Data
    do {
      rawToken = try Base64URL.decode(token)
    } catch {
      throw SessionManagerError.invalidSession
    }
    guard rawToken.count == 32 else {
      throw SessionManagerError.invalidSession
    }
    try await store.delete(tokenHash: WebAuthnCrypto.sha256(rawToken))
  }

  public func revokeAll(userID: UUID) async throws {
    try await store.deleteAll(userID: userID)
  }
}

public enum SessionManagerError: Error, Equatable, Sendable {
  case invalidTimeToLive
  case invalidSession
}
