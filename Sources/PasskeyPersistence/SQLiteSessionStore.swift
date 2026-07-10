import Foundation
import PasskeyServer

/// Durable hashed-session storage backed directly by SQLite.
public actor SQLiteSessionStore: SessionStore {
  private let database: SQLiteDatabase

  public init(path: String) throws {
    database = try SQLiteDatabase(path: path)
    try database.execute(
      """
      CREATE TABLE IF NOT EXISTS passkey_sessions (
        token_hash BLOB PRIMARY KEY NOT NULL,
        user_id TEXT NOT NULL,
        created_at REAL NOT NULL,
        expires_at REAL NOT NULL
      )
      """
    )
    try database.execute(
      "CREATE INDEX IF NOT EXISTS passkey_sessions_user_id ON passkey_sessions(user_id)"
    )
    try database.execute(
      "CREATE INDEX IF NOT EXISTS passkey_sessions_expires_at ON passkey_sessions(expires_at)"
    )
  }

  public func save(_ session: SessionRecord) throws {
    try database.transaction {
      if !(try database.rows(
        "SELECT 1 FROM passkey_sessions WHERE token_hash = ?",
        bindings: [.blob(session.tokenHash)]
      )).isEmpty {
        throw SessionStoreError.duplicateTokenHash
      }
      try database.execute(
        """
        INSERT INTO passkey_sessions (token_hash, user_id, created_at, expires_at)
        VALUES (?, ?, ?, ?)
        """,
        bindings: [
          .blob(session.tokenHash),
          .text(session.userID.uuidString),
          .double(session.createdAt.timeIntervalSince1970),
          .double(session.expiresAt.timeIntervalSince1970),
        ]
      )
    }
  }

  public func find(tokenHash: Data, at now: Date) throws -> SessionRecord? {
    let rows = try database.rows(
      """
      SELECT token_hash, user_id, created_at, expires_at
      FROM passkey_sessions WHERE token_hash = ?
      """,
      bindings: [.blob(tokenHash)]
    )
    guard let row = rows.first else { return nil }
    guard rows.count == 1,
      let userID = UUID(uuidString: try row.text(1))
    else {
      throw SQLitePersistenceError.corrupted("Invalid session row")
    }
    let expiresAt = Date(timeIntervalSince1970: try row.double(3))
    guard expiresAt > now else {
      try delete(tokenHash: tokenHash)
      return nil
    }
    return SessionRecord(
      tokenHash: try row.blob(0),
      userID: userID,
      createdAt: Date(timeIntervalSince1970: try row.double(2)),
      expiresAt: expiresAt
    )
  }

  public func delete(tokenHash: Data) throws {
    try database.execute(
      "DELETE FROM passkey_sessions WHERE token_hash = ?",
      bindings: [.blob(tokenHash)]
    )
  }

  public func deleteAll(userID: UUID) throws {
    try database.execute(
      "DELETE FROM passkey_sessions WHERE user_id = ?",
      bindings: [.text(userID.uuidString)]
    )
  }
}
