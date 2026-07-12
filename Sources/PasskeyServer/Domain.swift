import Foundation
import PasskeyCore

/// An RP-local account with a stable, opaque WebAuthn user handle.
public struct UserAccount: Equatable, Sendable {
  /// Database identity used by the application, not by the authenticator.
  public let id: UUID
  /// Stable opaque bytes given to WebAuthn as the RP-local user identity.
  public let userHandle: Data
  /// Human-entered account lookup name.
  public let username: String
  /// Human-readable label shown by account UI.
  public let displayName: String
  /// Time at which verified registration committed the account.
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
  /// Opaque authenticator-generated identifier used to select this credential.
  public let id: Data
  /// Application account that owns the credential.
  public let userID: UUID
  /// WebAuthn user handle bound to the owning account.
  public let userHandle: Data
  /// Parsed ES256 public key used for assertion verification.
  public let publicKey: COSEEC2PublicKey
  /// Original encoded COSE key retained for inspection and migration.
  public let rawPublicKey: Data
  /// Authenticator model identifier; all zeroes when not disclosed.
  public let aaguid: Data
  /// Latest accepted authenticator signature counter.
  public var signCount: UInt32
  /// Immutable flag indicating whether the credential may be backed up.
  public let backupEligible: Bool
  /// Latest signed backup state reported by the authenticator.
  public var backupState: Bool
  /// Time at which verified registration committed the credential.
  public let createdAt: Date
  /// Time of the latest accepted assertion, if one has occurred.
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
