import Foundation

/// Bit flags signed by the authenticator as part of authenticator data.
public struct AuthenticatorFlags: OptionSet, Equatable, Sendable {
  public let rawValue: UInt8

  public init(rawValue: UInt8) {
    self.rawValue = rawValue
  }

  public static let userPresent = Self(rawValue: 1 << 0)
  public static let userVerified = Self(rawValue: 1 << 2)
  public static let backupEligible = Self(rawValue: 1 << 3)
  public static let backupState = Self(rawValue: 1 << 4)
  public static let attestedCredentialData = Self(rawValue: 1 << 6)
  public static let extensionData = Self(rawValue: 1 << 7)

  public static let reservedMask: UInt8 = (1 << 1) | (1 << 5)
}

/// Registration-only public credential data embedded after the fixed header.
public struct AttestedCredentialData: Equatable, Sendable {
  public let aaguid: Data
  public let credentialID: Data
  public let credentialPublicKey: COSEEC2PublicKey
  public let rawCredentialPublicKey: Data

  public init(
    aaguid: Data,
    credentialID: Data,
    credentialPublicKey: COSEEC2PublicKey,
    rawCredentialPublicKey: Data
  ) {
    self.aaguid = aaguid
    self.credentialID = credentialID
    self.credentialPublicKey = credentialPublicKey
    self.rawCredentialPublicKey = rawCredentialPublicKey
  }
}

/// The signed authenticator data structure defined by WebAuthn.
///
/// Parsing rejects reserved flags, invalid backup-state combinations, trailing
/// bytes, malformed credential keys, and malformed extension CBOR.
public struct AuthenticatorData: Equatable, Sendable {
  public static let fixedHeaderLength = 37

  public let rawBytes: Data
  public let rpIDHash: Data
  public let flags: AuthenticatorFlags
  public let signCount: UInt32
  public let attestedCredential: AttestedCredentialData?
  public let extensions: CBORValue?

  /// Parses bytes while retaining the exact original representation used by
  /// assertion signature verification.
  public init(rawBytes: Data, cborLimits: CBORLimits = CBORLimits()) throws {
    guard rawBytes.count >= Self.fixedHeaderLength else {
      throw AuthenticatorDataError.tooShort(actual: rawBytes.count)
    }

    var cursor = try ByteCursor(rawBytes)
    let rpIDHash = try cursor.read(32)
    let flags = AuthenticatorFlags(rawValue: try cursor.readByte())
    let signCount = try cursor.readUInt32()

    guard flags.rawValue & AuthenticatorFlags.reservedMask == 0 else {
      throw AuthenticatorDataError.reservedFlagsSet(flags.rawValue)
    }
    guard !flags.contains(.backupState) || flags.contains(.backupEligible) else {
      throw AuthenticatorDataError.backupStateWithoutEligibility
    }

    var attestedCredential: AttestedCredentialData?
    if flags.contains(.attestedCredentialData) {
      let aaguid = try cursor.read(16)
      let credentialIDLength = Int(try cursor.readUInt16())
      guard credentialIDLength > 0 else {
        throw AuthenticatorDataError.emptyCredentialID
      }
      let credentialID = try cursor.read(credentialIDLength)
      let publicKeyBytes = try cursor.read(cursor.remainingCount)
      let decoded = try CBORDecoder.decodePrefix(publicKeyBytes, limits: cborLimits)
      guard decoded.consumed > 0 else {
        throw AuthenticatorDataError.missingCredentialPublicKey
      }
      let rawPublicKey = publicKeyBytes.prefix(decoded.consumed)
      attestedCredential = try AttestedCredentialData(
        aaguid: aaguid,
        credentialID: credentialID,
        credentialPublicKey: COSEEC2PublicKey(cbor: decoded.value),
        rawCredentialPublicKey: Data(rawPublicKey)
      )

      cursor = try ByteCursor(
        rawBytes, offset: rawBytes.count - publicKeyBytes.count + decoded.consumed)
    }

    var extensions: CBORValue?
    if flags.contains(.extensionData) {
      guard cursor.remainingCount > 0 else {
        throw AuthenticatorDataError.missingExtensionData
      }
      let extensionBytes = try cursor.read(cursor.remainingCount)
      extensions = try CBORDecoder.decode(extensionBytes, limits: cborLimits)
    }

    try cursor.requireEnd()

    self.rawBytes = rawBytes
    self.rpIDHash = rpIDHash
    self.flags = flags
    self.signCount = signCount
    self.attestedCredential = attestedCredential
    self.extensions = extensions
  }
}

/// Structural failures found before RP-specific flag policy is applied.
public enum AuthenticatorDataError: Error, Equatable, Sendable {
  case tooShort(actual: Int)
  case reservedFlagsSet(UInt8)
  case backupStateWithoutEligibility
  case emptyCredentialID
  case missingCredentialPublicKey
  case missingExtensionData
}

/// The CBOR registration envelope containing format, authenticator data, and an
/// attestation statement.
public struct AttestationObject: Equatable, Sendable {
  public let format: String
  public let authenticatorData: AuthenticatorData
  public let attestationStatement: CBORValue

  public init(rawBytes: Data, cborLimits: CBORLimits = CBORLimits()) throws {
    let value = try CBORDecoder.decode(rawBytes, limits: cborLimits)
    guard value.mapEntries != nil else {
      throw AttestationObjectError.expectedMap
    }
    guard let format = value.value(for: .textString("fmt"))?.textString else {
      throw AttestationObjectError.missingFormat
    }
    guard let authData = value.value(for: .textString("authData"))?.byteString else {
      throw AttestationObjectError.missingAuthenticatorData
    }
    guard let statement = value.value(for: .textString("attStmt")), statement.mapEntries != nil
    else {
      throw AttestationObjectError.missingAttestationStatement
    }

    self.format = format
    self.authenticatorData = try AuthenticatorData(rawBytes: authData, cborLimits: cborLimits)
    self.attestationStatement = statement
  }
}

/// Missing or incorrectly typed mandatory attestation object fields.
public enum AttestationObjectError: Error, Equatable, Sendable {
  case expectedMap
  case missingFormat
  case missingAuthenticatorData
  case missingAttestationStatement
}
