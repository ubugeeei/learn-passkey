import Crypto
import Foundation
import PasskeyCore

@testable import PasskeyServer

struct TestAuthenticator {
  let privateKey: P256.Signing.PrivateKey
  let credentialID: Data

  init(
    privateKey: P256.Signing.PrivateKey = P256.Signing.PrivateKey(),
    credentialID: Data = Data((0..<32).map { UInt8(0xa0 + ($0 % 16)) })
  ) {
    self.privateKey = privateKey
    self.credentialID = credentialID
  }

  func registrationRequest(
    options: RegistrationOptionsResponse,
    origin: String = "https://passkeys.example.com",
    rpID: String = "passkeys.example.com",
    ceremonyType: String = "webauthn.create",
    includeUserPresence: Bool = true,
    includeUserVerification: Bool = true,
    backupEligible: Bool = false,
    embeddedCredentialID: Data? = nil,
    publicKeyX963: Data? = nil,
    attestationFormat: String = "none",
    includeAttestationStatement: Bool = false
  ) throws -> CompleteRegistrationRequest {
    let clientDataJSON = try makeClientDataJSON(
      type: ceremonyType,
      challenge: options.publicKey.challenge,
      origin: origin
    )
    let authData = registrationAuthenticatorData(
      rpID: rpID,
      includeUserPresence: includeUserPresence,
      includeUserVerification: includeUserVerification,
      backupEligible: backupEligible,
      embeddedCredentialID: embeddedCredentialID,
      publicKeyX963: publicKeyX963
    )
    let attestationObject = TestCBOREncoder.map([
      (.text("fmt"), .text(attestationFormat)),
      (.text("authData"), .bytes(authData)),
      (
        .text("attStmt"),
        .map(includeAttestationStatement ? [(.text("unexpected"), .unsigned(1))] : [])
      ),
    ])
    let credentialID = Base64URL.encode(credentialID)
    return CompleteRegistrationRequest(
      ceremonyID: options.ceremonyID,
      id: credentialID,
      rawId: credentialID,
      type: .publicKey,
      response: RegistrationCredentialResponse(
        clientDataJSON: Base64URL.encode(clientDataJSON),
        attestationObject: Base64URL.encode(attestationObject)
      )
    )
  }

  func authenticationRequest(
    options: AuthenticationOptionsResponse,
    userHandle: String?,
    signCount: UInt32,
    origin: String = "https://passkeys.example.com",
    rpID: String = "passkeys.example.com",
    ceremonyType: String = "webauthn.get",
    includeUserPresence: Bool = true,
    includeUserVerification: Bool = true,
    backupEligible: Bool = false,
    signingKey: P256.Signing.PrivateKey? = nil
  ) throws -> CompleteAuthenticationRequest {
    let clientDataJSON = try makeClientDataJSON(
      type: ceremonyType,
      challenge: options.publicKey.challenge,
      origin: origin
    )
    let authData = assertionAuthenticatorData(
      rpID: rpID,
      signCount: signCount,
      includeUserPresence: includeUserPresence,
      backupEligible: backupEligible,
      includeUserVerification: includeUserVerification
    )
    let clientDataHash = Data(SHA256.hash(data: clientDataJSON))
    let signature = try (signingKey ?? privateKey).signature(
      for: authData + clientDataHash
    ).derRepresentation
    let credentialID = Base64URL.encode(credentialID)
    return CompleteAuthenticationRequest(
      ceremonyID: options.ceremonyID,
      id: credentialID,
      rawId: credentialID,
      type: .publicKey,
      response: AuthenticationCredentialResponse(
        clientDataJSON: Base64URL.encode(clientDataJSON),
        authenticatorData: Base64URL.encode(authData),
        signature: Base64URL.encode(signature),
        userHandle: userHandle
      )
    )
  }

  private func registrationAuthenticatorData(
    rpID: String,
    includeUserPresence: Bool,
    includeUserVerification: Bool,
    backupEligible: Bool,
    embeddedCredentialID: Data?,
    publicKeyX963: Data?
  ) -> Data {
    var flags = AuthenticatorFlags.attestedCredentialData.rawValue
    if includeUserPresence {
      flags |= AuthenticatorFlags.userPresent.rawValue
    }
    if includeUserVerification {
      flags |= AuthenticatorFlags.userVerified.rawValue
    }
    if backupEligible {
      flags |= AuthenticatorFlags.backupEligible.rawValue
    }

    let publicKey = publicKeyX963 ?? privateKey.publicKey.x963Representation
    let x = publicKey.subdata(in: 1..<33)
    let y = publicKey.subdata(in: 33..<65)
    let coseKey = TestCBOREncoder.map([
      (.unsigned(1), .unsigned(2)),
      (.unsigned(3), .negative(-7)),
      (.negative(-1), .unsigned(1)),
      (.negative(-2), .bytes(x)),
      (.negative(-3), .bytes(y)),
    ])
    let embeddedCredentialID = embeddedCredentialID ?? credentialID
    return Data(SHA256.hash(data: Data(rpID.utf8)))
      + Data([flags, 0, 0, 0, 0])
      + Data(repeating: 0, count: 16)
      + UInt16(embeddedCredentialID.count).networkBytes
      + embeddedCredentialID
      + coseKey
  }

  private func assertionAuthenticatorData(
    rpID: String,
    signCount: UInt32,
    includeUserPresence: Bool,
    backupEligible: Bool,
    includeUserVerification: Bool
  ) -> Data {
    var flags: UInt8 = 0
    if includeUserPresence {
      flags |= AuthenticatorFlags.userPresent.rawValue
    }
    if includeUserVerification {
      flags |= AuthenticatorFlags.userVerified.rawValue
    }
    if backupEligible {
      flags |= AuthenticatorFlags.backupEligible.rawValue
    }
    return Data(SHA256.hash(data: Data(rpID.utf8)))
      + Data([flags])
      + signCount.networkBytes
  }

  private func makeClientDataJSON(
    type: String,
    challenge: String,
    origin: String
  ) throws -> Data {
    try JSONSerialization.data(
      withJSONObject: [
        "type": type,
        "challenge": challenge,
        "origin": origin,
        "crossOrigin": false,
      ],
      options: [.sortedKeys]
    )
  }
}

extension UInt16 {
  fileprivate var networkBytes: Data {
    Data([UInt8((self >> 8) & 0xff), UInt8(self & 0xff)])
  }
}

extension UInt32 {
  fileprivate var networkBytes: Data {
    Data([
      UInt8((self >> 24) & 0xff),
      UInt8((self >> 16) & 0xff),
      UInt8((self >> 8) & 0xff),
      UInt8(self & 0xff),
    ])
  }
}

private enum TestCBOREncoder {
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
    preconditionFailure("Fixture encoder only needs values up to UInt16")
  }
}
