import Foundation
import Testing

@testable import PasskeyServer

@Suite struct SessionTests {
  private let userID = UUID(uuidString: "1E7A6F0D-F0C7-45D2-A9B5-AAB7476EEA87")!
  private let issuedAt = Date(timeIntervalSince1970: 1_800_000_000)

  @Test func storesOnlyTheTokenHashAndAuthenticatesBearer() async throws {
    let store = InMemorySessionStore()
    let manager = try makeManager(store: store)

    let session = try await manager.issue(userID: userID)

    #expect(try await manager.authenticate(token: session.token) == userID)
    #expect(session.expiresAt == issuedAt.addingTimeInterval(3_600))
    #expect(await store.count == 1)
  }

  @Test func expiresAndRemovesSession() async throws {
    let store = InMemorySessionStore()
    let now = LockedDate(issuedAt)
    let manager = try makeManager(store: store, now: now)
    let session = try await manager.issue(userID: userID)

    now.value = issuedAt.addingTimeInterval(3_600)

    await #expect(throws: SessionManagerError.invalidSession) {
      try await manager.authenticate(token: session.token)
    }
    #expect(await store.count == 0)
  }

  @Test func revokeMakesBearerUnusable() async throws {
    let manager = try makeManager()
    let session = try await manager.issue(userID: userID)

    try await manager.revoke(token: session.token)

    await #expect(throws: SessionManagerError.invalidSession) {
      try await manager.authenticate(token: session.token)
    }
  }

  private func makeManager(
    store: InMemorySessionStore = InMemorySessionStore(),
    now: LockedDate? = nil
  ) throws -> SessionManager {
    let clock = now ?? LockedDate(issuedAt)
    return try SessionManager(
      store: store,
      timeToLive: 3_600,
      now: { clock.value },
      randomBytes: { count in Data(repeating: 0x42, count: count) }
    )
  }
}

private final class LockedDate: @unchecked Sendable {
  private let lock = NSLock()
  private var storedValue: Date

  init(_ value: Date) {
    storedValue = value
  }

  var value: Date {
    get { lock.withLock { storedValue } }
    set { lock.withLock { storedValue = newValue } }
  }
}
