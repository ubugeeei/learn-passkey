import Foundation
import PasskeyServer

/// Durable ceremony storage with transactional read-and-delete consumption.
///
/// `BEGIN IMMEDIATE` ensures two processes sharing the same SQLite file cannot
/// both read a ceremony before either deletes it. This is suitable for a
/// single-node lab; production topology still determines the right shared store.
public actor SQLiteCeremonyStore: CeremonyStore {
  private let database: SQLiteDatabase

  public init(path: String) throws {
    database = try SQLiteDatabase(path: path)
    try database.execute(
      """
      CREATE TABLE IF NOT EXISTS passkey_ceremonies (
        id TEXT PRIMARY KEY NOT NULL,
        challenge BLOB NOT NULL,
        purpose INTEGER NOT NULL CHECK (purpose IN (1, 2)),
        user_id TEXT,
        user_handle BLOB,
        username TEXT,
        display_name TEXT,
        user_created_at REAL,
        expected_user_id TEXT,
        require_user_handle INTEGER,
        expires_at REAL NOT NULL
      )
      """
    )
    try database.execute(
      "CREATE INDEX IF NOT EXISTS passkey_ceremonies_expires_at ON passkey_ceremonies(expires_at)"
    )
  }

  public func save(_ state: CeremonyState) throws {
    let encoded = Self.encode(state.purpose)
    try database.transaction {
      if !(try database.rows(
        "SELECT 1 FROM passkey_ceremonies WHERE id = ?",
        bindings: [.text(state.id)]
      )).isEmpty {
        throw CeremonyStoreError.duplicateID
      }
      try database.execute(
        """
        INSERT INTO passkey_ceremonies (
          id, challenge, purpose, user_id, user_handle, username,
          display_name, user_created_at, expected_user_id,
          require_user_handle, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        bindings: [
          .text(state.id),
          .blob(state.challenge),
          .integer(encoded.kind),
          encoded.userID.map(SQLiteValue.text) ?? .null,
          encoded.userHandle.map(SQLiteValue.blob) ?? .null,
          encoded.username.map(SQLiteValue.text) ?? .null,
          encoded.displayName.map(SQLiteValue.text) ?? .null,
          encoded.userCreatedAt.map(SQLiteValue.double) ?? .null,
          encoded.expectedUserID.map(SQLiteValue.text) ?? .null,
          encoded.requireUserHandle.map { .integer($0 ? 1 : 0) } ?? .null,
          .double(state.expiresAt.timeIntervalSince1970),
        ]
      )
    }
  }

  public func consume(id: String, at now: Date) throws -> CeremonyState {
    let state: CeremonyState = try database.transaction {
      let rows = try database.rows(
        """
        SELECT id, challenge, purpose, user_id, user_handle, username,
               display_name, user_created_at, expected_user_id,
               require_user_handle, expires_at
        FROM passkey_ceremonies WHERE id = ?
        """,
        bindings: [.text(id)]
      )
      guard let row = rows.first else {
        throw CeremonyStoreError.notFound
      }
      guard rows.count == 1 else {
        throw SQLitePersistenceError.corrupted("Duplicate ceremony ID")
      }
      let state = try Self.state(from: row)
      try database.execute(
        "DELETE FROM passkey_ceremonies WHERE id = ?",
        bindings: [.text(id)]
      )
      return state
    }
    guard state.expiresAt > now else {
      throw CeremonyStoreError.expired
    }
    return state
  }

  private static func state(from row: SQLiteRow) throws -> CeremonyState {
    let purpose: CeremonyPurpose
    switch try row.integer(2) {
    case 1:
      guard let userIDString = try row.optionalText(3),
        let userID = UUID(uuidString: userIDString),
        let userHandle = try row.optionalBlob(4),
        let username = try row.optionalText(5),
        let displayName = try row.optionalText(6),
        let createdAt = try row.optionalDouble(7)
      else {
        throw SQLitePersistenceError.corrupted("Incomplete registration ceremony")
      }
      purpose = .registration(
        PendingRegistration(
          user: UserAccount(
            id: userID,
            userHandle: userHandle,
            username: username,
            displayName: displayName,
            createdAt: Date(timeIntervalSince1970: createdAt)
          )
        )
      )
    case 2:
      let expectedUserID: UUID?
      if let value = try row.optionalText(8) {
        guard let parsed = UUID(uuidString: value) else {
          throw SQLitePersistenceError.corrupted("Invalid expected user UUID")
        }
        expectedUserID = parsed
      } else {
        expectedUserID = nil
      }
      let required = try row.integer(9)
      guard required == 0 || required == 1 else {
        throw SQLitePersistenceError.corrupted("Invalid user-handle policy")
      }
      purpose = .authentication(
        expectedUserID: expectedUserID,
        requireUserHandle: required == 1
      )
    default:
      throw SQLitePersistenceError.corrupted("Unknown ceremony purpose")
    }

    return CeremonyState(
      id: try row.text(0),
      challenge: try row.blob(1),
      purpose: purpose,
      expiresAt: Date(timeIntervalSince1970: try row.double(10))
    )
  }

  private static func encode(_ purpose: CeremonyPurpose) -> EncodedPurpose {
    switch purpose {
    case .registration(let pending):
      EncodedPurpose(
        kind: 1,
        userID: pending.user.id.uuidString,
        userHandle: pending.user.userHandle,
        username: pending.user.username,
        displayName: pending.user.displayName,
        userCreatedAt: pending.user.createdAt.timeIntervalSince1970,
        expectedUserID: nil,
        requireUserHandle: nil
      )
    case .authentication(let expectedUserID, let requireUserHandle):
      EncodedPurpose(
        kind: 2,
        userID: nil,
        userHandle: nil,
        username: nil,
        displayName: nil,
        userCreatedAt: nil,
        expectedUserID: expectedUserID?.uuidString,
        requireUserHandle: requireUserHandle
      )
    }
  }
}

private struct EncodedPurpose {
  let kind: Int64
  let userID: String?
  let userHandle: Data?
  let username: String?
  let displayName: String?
  let userCreatedAt: Double?
  let expectedUserID: String?
  let requireUserHandle: Bool?
}
