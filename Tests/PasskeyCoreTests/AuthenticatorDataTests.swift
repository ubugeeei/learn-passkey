import Foundation
import Testing

@testable import PasskeyCore

@Suite struct AuthenticatorDataTests {
  private let rpIDHash = Data(repeating: 0x11, count: 32)
  private let credentialID = Data([0xca, 0xfe, 0xba, 0xbe])

  @Test func parsesRegistrationAuthenticatorDataAndCOSEKey() throws {
    let raw = makeRegistrationAuthenticatorData()

    let parsed = try AuthenticatorData(rawBytes: raw)

    #expect(parsed.rpIDHash == rpIDHash)
    #expect(parsed.flags.contains(.userPresent))
    #expect(parsed.flags.contains(.userVerified))
    #expect(parsed.signCount == 7)
    #expect(parsed.attestedCredential?.credentialID == credentialID)
    #expect(parsed.attestedCredential?.credentialPublicKey.x == Data(repeating: 0x22, count: 32))
    #expect(parsed.attestedCredential?.credentialPublicKey.y == Data(repeating: 0x33, count: 32))
    #expect(parsed.attestedCredential?.credentialPublicKey.x963Representation.count == 65)
  }

  @Test func rejectsReservedFlagsAndInvalidBackupState() {
    #expect(throws: AuthenticatorDataError.reservedFlagsSet(0x03)) {
      try AuthenticatorData(rawBytes: fixedHeader(flags: 0x03))
    }
    #expect(throws: AuthenticatorDataError.backupStateWithoutEligibility) {
      try AuthenticatorData(rawBytes: fixedHeader(flags: 0x11))
    }
  }

  @Test func parsesNoneAttestationObject() throws {
    let authData = makeRegistrationAuthenticatorData()
    let object = TestCBOR.map([
      (.text("fmt"), .text("none")),
      (.text("authData"), .bytes(authData)),
      (.text("attStmt"), .map([])),
    ])

    let parsed = try AttestationObject(rawBytes: object)

    #expect(parsed.format == "none")
    #expect(parsed.authenticatorData.attestedCredential?.credentialID == credentialID)
    #expect(parsed.attestationStatement == .map([]))
  }

  private func fixedHeader(flags: UInt8) -> Data {
    rpIDHash + Data([flags, 0, 0, 0, 7])
  }

  private func makeRegistrationAuthenticatorData() -> Data {
    let flags =
      AuthenticatorFlags.userPresent.rawValue
      | AuthenticatorFlags.userVerified.rawValue
      | AuthenticatorFlags.attestedCredentialData.rawValue
    let credentialLength = Data([
      UInt8((credentialID.count >> 8) & 0xff),
      UInt8(credentialID.count & 0xff),
    ])
    return fixedHeader(flags: flags)
      + Data(repeating: 0, count: 16)
      + credentialLength
      + credentialID
      + makeCOSEKey()
  }

  private func makeCOSEKey() -> Data {
    TestCBOR.map([
      (.unsigned(1), .unsigned(2)),
      (.unsigned(3), .negative(-7)),
      (.negative(-1), .unsigned(1)),
      (.negative(-2), .bytes(Data(repeating: 0x22, count: 32))),
      (.negative(-3), .bytes(Data(repeating: 0x33, count: 32))),
    ])
  }
}

private enum TestCBOR {
  enum Value {
    case unsigned(UInt64)
    case negative(Int64)
    case bytes(Data)
    case text(String)
    case map([(Value, Value)])
  }

  static func map(_ entries: [(Value, Value)]) -> Data {
    encode(.map(entries))
  }

  static func encode(_ value: Value) -> Data {
    switch value {
    case .unsigned(let value):
      return head(major: 0, value: value)
    case .negative(let value):
      return head(major: 1, value: UInt64(-1 - value))
    case .bytes(let value):
      return head(major: 2, value: UInt64(value.count)) + value
    case .text(let value):
      let data = Data(value.utf8)
      return head(major: 3, value: UInt64(data.count)) + data
    case .map(let entries):
      let encoded = entries.map { (encode($0.0), encode($0.1)) }
        .sorted { left, right in
          left.0.count == right.0.count
            ? left.0.lexicographicallyPrecedes(right.0)
            : left.0.count < right.0.count
        }
      return head(major: 5, value: UInt64(encoded.count))
        + encoded.reduce(into: Data()) { result, entry in
          result.append(entry.0)
          result.append(entry.1)
        }
    }
  }

  private static func head(major: UInt8, value: UInt64) -> Data {
    if value < 24 {
      return Data([(major << 5) | UInt8(value)])
    }
    if value <= UInt8.max {
      return Data([(major << 5) | 24, UInt8(value)])
    }
    if value <= UInt16.max {
      return Data([
        (major << 5) | 25,
        UInt8((value >> 8) & 0xff),
        UInt8(value & 0xff),
      ])
    }
    preconditionFailure("Test encoder only needs values up to UInt16")
  }
}
