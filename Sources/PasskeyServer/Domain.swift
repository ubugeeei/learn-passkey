import Foundation
import PasskeyCore

/// An RP-local account with a stable, opaque WebAuthn user handle.
public struct UserAccount: Equatable, Sendable {
  public let id: UUID
  public let userHandle: Data
  public let username: String
  public let displayName: String
  public let createdAt: Date

  public init(
    id: UUID,
    userHandle: Data,
    username: String,
    displayName: String,
    createdAt: Date
  ) {
    self.id = id
    self.userHandle = userHandle
    self.username = username
    self.displayName = displayName
    self.createdAt = createdAt
  }
}

/// Public credential state stored by the RP after successful registration.
///
/// This record never contains a Passkey private key or biometric information.
/// Mutable fields are limited to counter, backup state, and last-use metadata.
public struct CredentialRecord: Equatable, Sendable {
  public let id: Data
  public let userID: UUID
  public let userHandle: Data
  public let publicKey: COSEEC2PublicKey
  public let rawPublicKey: Data
  public let aaguid: Data
  public var signCount: UInt32
  public let backupEligible: Bool
  public var backupState: Bool
  public let createdAt: Date
  public var lastUsedAt: Date?

  public init(
    id: Data,
    userID: UUID,
    userHandle: Data,
    publicKey: COSEEC2PublicKey,
    rawPublicKey: Data,
    aaguid: Data,
    signCount: UInt32,
    backupEligible: Bool,
    backupState: Bool,
    createdAt: Date,
    lastUsedAt: Date? = nil
  ) {
    self.id = id
    self.userID = userID
    self.userHandle = userHandle
    self.publicKey = publicKey
    self.rawPublicKey = rawPublicKey
    self.aaguid = aaguid
    self.signCount = signCount
    self.backupEligible = backupEligible
    self.backupState = backupState
    self.createdAt = createdAt
    self.lastUsedAt = lastUsedAt
  }
}

/// Account data held only inside a registration ceremony until verification.
public struct PendingRegistration: Equatable, Sendable {
  public let user: UserAccount

  public init(user: UserAccount) {
    self.user = user
  }
}

/// Server-side context that prevents registration/authentication confusion.
public enum CeremonyPurpose: Equatable, Sendable {
  case registration(PendingRegistration)
  case authentication(expectedUserID: UUID?, requireUserHandle: Bool)
}

/// Single-use server state that binds a challenge to purpose and expiry.
public struct CeremonyState: Equatable, Sendable {
  public let id: String
  public let challenge: Data
  public let purpose: CeremonyPurpose
  public let expiresAt: Date

  public init(id: String, challenge: Data, purpose: CeremonyPurpose, expiresAt: Date) {
    self.id = id
    self.challenge = challenge
    self.purpose = purpose
    self.expiresAt = expiresAt
  }
}
