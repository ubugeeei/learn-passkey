import CSQLite
import Foundation

/// Failures raised by the direct SQLite adapter.
public enum SQLitePersistenceError: Error, Equatable, Sendable {
  case open(code: Int32, message: String)
  case execute(code: Int32, message: String)
  case prepare(code: Int32, message: String)
  case bind(code: Int32, message: String)
  case step(code: Int32, message: String)
  case corrupted(String)
}

enum SQLiteValue: Sendable {
  case null
  case integer(Int64)
  case double(Double)
  case text(String)
  case blob(Data)
}

/// A connection is owned by one persistence actor. FULLMUTEX is a second line
/// of defense; the actor is the primary Swift concurrency boundary.
final class SQLiteDatabase: @unchecked Sendable {
  private var connection: OpaquePointer?

  init(path: String) throws {
    let flags = SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX
    let result = sqlite3_open_v2(path, &connection, flags, nil)
    guard result == SQLITE_OK, connection != nil else {
      let message = connection.map { String(cString: sqlite3_errmsg($0)) } ?? "No connection"
      if let connection { sqlite3_close(connection) }
      throw SQLitePersistenceError.open(code: result, message: message)
    }

    try execute("PRAGMA foreign_keys = ON")
    _ = try rows("PRAGMA journal_mode = WAL")
    try execute("PRAGMA synchronous = NORMAL")
    sqlite3_busy_timeout(connection, 5_000)
  }

  deinit {
    if let connection {
      sqlite3_close(connection)
    }
  }

  @discardableResult
  func execute(_ sql: String, bindings: [SQLiteValue] = []) throws -> Int {
    let statement = try prepare(sql)
    defer { sqlite3_finalize(statement) }
    try bind(bindings, to: statement)
    let result = sqlite3_step(statement)
    guard result == SQLITE_DONE else {
      throw error(.step, code: result)
    }
    return Int(sqlite3_changes(connection))
  }

  func rows(_ sql: String, bindings: [SQLiteValue] = []) throws -> [SQLiteRow] {
    let statement = try prepare(sql)
    defer { sqlite3_finalize(statement) }
    try bind(bindings, to: statement)

    var rows: [SQLiteRow] = []
    while true {
      let result = sqlite3_step(statement)
      switch result {
      case SQLITE_ROW:
        rows.append(SQLiteRow(statement: statement))
      case SQLITE_DONE:
        return rows
      default:
        throw error(.step, code: result)
      }
    }
  }

  func transaction<T>(_ body: () throws -> T) throws -> T {
    try execute("BEGIN IMMEDIATE")
    do {
      let result = try body()
      try execute("COMMIT")
      return result
    } catch {
      _ = try? execute("ROLLBACK")
      throw error
    }
  }

  private func prepare(_ sql: String) throws -> OpaquePointer {
    var statement: OpaquePointer?
    let result = sqlite3_prepare_v2(connection, sql, -1, &statement, nil)
    guard result == SQLITE_OK, let statement else {
      throw error(.prepare, code: result)
    }
    return statement
  }

  private func bind(_ values: [SQLiteValue], to statement: OpaquePointer) throws {
    for (offset, value) in values.enumerated() {
      let index = Int32(offset + 1)
      let result: Int32
      switch value {
      case .null:
        result = sqlite3_bind_null(statement, index)
      case .integer(let value):
        result = sqlite3_bind_int64(statement, index, value)
      case .double(let value):
        result = sqlite3_bind_double(statement, index, value)
      case .text(let value):
        result = sqlite3_bind_text(statement, index, value, -1, sqliteTransient)
      case .blob(let value):
        result = value.withUnsafeBytes { bytes in
          sqlite3_bind_blob(
            statement,
            index,
            bytes.baseAddress,
            Int32(bytes.count),
            sqliteTransient
          )
        }
      }
      guard result == SQLITE_OK else {
        throw error(.bind, code: result)
      }
    }
  }

  private enum Operation {
    case execute
    case prepare
    case bind
    case step
  }

  private func error(_ operation: Operation, code: Int32) -> SQLitePersistenceError {
    let message = connection.map { String(cString: sqlite3_errmsg($0)) } ?? "No connection"
    switch operation {
    case .execute: return .execute(code: code, message: message)
    case .prepare: return .prepare(code: code, message: message)
    case .bind: return .bind(code: code, message: message)
    case .step: return .step(code: code, message: message)
    }
  }
}

struct SQLiteRow {
  private let values: [SQLiteColumn]

  init(statement: OpaquePointer) {
    values = (0..<sqlite3_column_count(statement)).map { index in
      switch sqlite3_column_type(statement, index) {
      case SQLITE_INTEGER:
        .integer(sqlite3_column_int64(statement, index))
      case SQLITE_FLOAT:
        .double(sqlite3_column_double(statement, index))
      case SQLITE_TEXT:
        .text(String(cString: sqlite3_column_text(statement, index)))
      case SQLITE_BLOB:
        if let bytes = sqlite3_column_blob(statement, index) {
          .blob(Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, index))))
        } else {
          .blob(Data())
        }
      default:
        .null
      }
    }
  }

  func text(_ index: Int) throws -> String {
    guard case .text(let value) = values[index] else {
      throw SQLitePersistenceError.corrupted("Expected text at column \(index)")
    }
    return value
  }

  func optionalText(_ index: Int) throws -> String? {
    if case .null = values[index] { return nil }
    return try text(index)
  }

  func blob(_ index: Int) throws -> Data {
    guard case .blob(let value) = values[index] else {
      throw SQLitePersistenceError.corrupted("Expected blob at column \(index)")
    }
    return value
  }

  func optionalBlob(_ index: Int) throws -> Data? {
    if case .null = values[index] { return nil }
    return try blob(index)
  }

  func integer(_ index: Int) throws -> Int64 {
    guard case .integer(let value) = values[index] else {
      throw SQLitePersistenceError.corrupted("Expected integer at column \(index)")
    }
    return value
  }

  func double(_ index: Int) throws -> Double {
    switch values[index] {
    case .double(let value): return value
    case .integer(let value): return Double(value)
    default:
      throw SQLitePersistenceError.corrupted("Expected number at column \(index)")
    }
  }

  func optionalDouble(_ index: Int) throws -> Double? {
    if case .null = values[index] { return nil }
    return try double(index)
  }
}

private enum SQLiteColumn {
  case null
  case integer(Int64)
  case double(Double)
  case text(String)
  case blob(Data)
}

private let sqliteTransient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
