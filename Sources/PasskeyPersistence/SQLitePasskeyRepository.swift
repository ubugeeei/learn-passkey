import Foundation
import PasskeyCore
import PasskeyServer

/// A transactional SQLite implementation of the account/credential repository.
///
/// The actor owns one FULLMUTEX connection. `BEGIN IMMEDIATE` serializes the
/// uniqueness checks and inserts across other SQLite connections using the same
/// database file, so account plus first credential commit atomically.
public actor SQLitePasskeyRepository: PasskeyRepository {
  private let database: SQLiteDatabase

  public init(path: String) throws {
    database = try SQLiteDatabase(path: path)
    try database.execute(
      """
      CREATE TABLE IF NOT EXISTS passkey_users (
        id TEXT PRIMARY KEY NOT NULL,
        user_handle BLOB NOT NULL UNIQUE,
        username TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
        created_at REAL NOT NULL
      )
      """
    )
    try database.execute(
      """
      CREATE TABLE IF NOT EXISTS passkey_credentials (
        id BLOB PRIMARY KEY NOT NULL,
        user_id TEXT NOT NULL,
        user_handle BLOB NOT NULL,
        raw_public_key BLOB NOT NULL,
        aaguid BLOB NOT NULL,
        algorithm INTEGER NOT NULL,
        curve INTEGER NOT NULL,
        x BLOB NOT NULL,
        y BLOB NOT NULL,
        sign_count INTEGER NOT NULL CHECK (sign_count >= 0),
        backup_eligible INTEGER NOT NULL CHECK (backup_eligible IN (0, 1)),
        backup_state INTEGER NOT NULL CHECK (backup_state IN (0, 1)),
        created_at REAL NOT NULL,
        last_used_at REAL,
        FOREIGN KEY (user_id) REFERENCES passkey_users(id) ON DELETE CASCADE,
        CHECK (length(aaguid) = 16),
        CHECK (length(x) = 32),
        CHECK (length(y) = 32),
        CHECK (backup_state = 0 OR backup_eligible = 1)
      )
      """
    )
    try database.execute(
      "CREATE INDEX IF NOT EXISTS passkey_credentials_user_id ON passkey_credentials(user_id)"
    )
  }

  public func user(named username: String) throws -> UserAccount? {
    try findUser(
      sql:
        "SELECT id, user_handle, username, display_name, created_at FROM passkey_users WHERE username = ?",
      bindings: [.text(username)]
    )
  }

  public func user(id: UUID) throws -> UserAccount? {
    try findUser(
      sql:
        "SELECT id, user_handle, username, display_name, created_at FROM passkey_users WHERE id = ?",
      bindings: [.text(id.uuidString)]
    )
  }

  public func credential(id: Data) throws -> CredentialRecord? {
    try findCredential(
      sql: Self.credentialSelect + " WHERE id = ?",
      bindings: [.blob(id)]
    )
  }

  public func credentials(userID: UUID) throws -> [CredentialRecord] {
    try database.rows(
      Self.credentialSelect + " WHERE user_id = ? ORDER BY created_at, id",
      bindings: [.text(userID.uuidString)]
    ).map(Self.credential(from:))
  }

  public func create(user: UserAccount, credential: CredentialRecord) throws {
    guard user.id == credential.userID, user.userHandle == credential.userHandle else {
      throw SQLitePersistenceError.corrupted("Credential account binding is inconsistent")
    }

    try database.transaction {
      if try findUser(
        sql:
          "SELECT id, user_handle, username, display_name, created_at FROM passkey_users WHERE username = ?",
        bindings: [.text(user.username)]
      ) != nil {
        throw PasskeyRepositoryError.usernameAlreadyExists
      }
      if try findCredential(
        sql: Self.credentialSelect + " WHERE id = ?",
        bindings: [.blob(credential.id)]
      ) != nil {
        throw PasskeyRepositoryError.credentialAlreadyExists
      }

      try database.execute(
        """
        INSERT INTO passkey_users (id, user_handle, username, display_name, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        bindings: [
          .text(user.id.uuidString),
          .blob(user.userHandle),
          .text(user.username),
          .text(user.displayName),
          .double(user.createdAt.timeIntervalSince1970),
        ]
      )
      try database.execute(
        """
        INSERT INTO passkey_credentials (
          id, user_id, user_handle, raw_public_key, aaguid,
          algorithm, curve, x, y, sign_count,
          backup_eligible, backup_state, created_at, last_used_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        bindings: [
          .blob(credential.id),
          .text(credential.userID.uuidString),
          .blob(credential.userHandle),
          .blob(credential.rawPublicKey),
          .blob(credential.aaguid),
          .integer(credential.publicKey.algorithm),
          .integer(credential.publicKey.curve),
          .blob(credential.publicKey.x),
          .blob(credential.publicKey.y),
          .integer(Int64(credential.signCount)),
          .integer(credential.backupEligible ? 1 : 0),
          .integer(credential.backupState ? 1 : 0),
          .double(credential.createdAt.timeIntervalSince1970),
          credential.lastUsedAt.map { .double($0.timeIntervalSince1970) } ?? .null,
        ]
      )
    }
  }

  public func updateAfterAuthentication(
    credentialID: Data,
    signCount: UInt32,
    backupState: Bool,
    usedAt: Date
  ) throws {
    let changes = try database.execute(
      """
      UPDATE passkey_credentials
      SET sign_count = ?, backup_state = ?, last_used_at = ?
      WHERE id = ?
      """,
      bindings: [
        .integer(Int64(signCount)),
        .integer(backupState ? 1 : 0),
        .double(usedAt.timeIntervalSince1970),
        .blob(credentialID),
      ]
    )
    guard changes == 1 else {
      throw PasskeyRepositoryError.credentialNotFound
    }
  }

  private func findUser(
    sql: String,
    bindings: [SQLiteValue]
  ) throws -> UserAccount? {
    let rows = try database.rows(sql, bindings: bindings)
    guard rows.count <= 1 else {
      throw SQLitePersistenceError.corrupted("User uniqueness constraint was violated")
    }
    return try rows.first.map(Self.user(from:))
  }

  private func findCredential(
    sql: String,
    bindings: [SQLiteValue]
  ) throws -> CredentialRecord? {
    let rows = try database.rows(sql, bindings: bindings)
    guard rows.count <= 1 else {
      throw SQLitePersistenceError.corrupted("Credential uniqueness constraint was violated")
    }
    return try rows.first.map(Self.credential(from:))
  }

  private static func user(from row: SQLiteRow) throws -> UserAccount {
    guard let id = UUID(uuidString: try row.text(0)) else {
      throw SQLitePersistenceError.corrupted("Invalid user UUID")
    }
    return UserAccount(
      id: id,
      userHandle: try row.blob(1),
      username: try row.text(2),
      displayName: try row.text(3),
      createdAt: Date(timeIntervalSince1970: try row.double(4))
    )
  }

  private static func credential(from row: SQLiteRow) throws -> CredentialRecord {
    guard let userID = UUID(uuidString: try row.text(1)) else {
      throw SQLitePersistenceError.corrupted("Invalid credential user UUID")
    }
    let signCount = try row.integer(9)
    guard signCount >= 0, signCount <= UInt32.max else {
      throw SQLitePersistenceError.corrupted("Signature counter is out of range")
    }
    return try CredentialRecord(
      id: row.blob(0),
      userID: userID,
      userHandle: row.blob(2),
      publicKey: COSEEC2PublicKey(
        algorithm: row.integer(5),
        curve: row.integer(6),
        x: row.blob(7),
        y: row.blob(8)
      ),
      rawPublicKey: row.blob(3),
      aaguid: row.blob(4),
      signCount: UInt32(signCount),
      backupEligible: row.integer(10) == 1,
      backupState: row.integer(11) == 1,
      createdAt: Date(timeIntervalSince1970: row.double(12)),
      lastUsedAt: try row.optionalDouble(13).map(Date.init(timeIntervalSince1970:))
    )
  }

  private static let credentialSelect = """
    SELECT id, user_id, user_handle, raw_public_key, aaguid,
           algorithm, curve, x, y, sign_count,
           backup_eligible, backup_state, created_at, last_used_at
    FROM passkey_credentials
    """
}
