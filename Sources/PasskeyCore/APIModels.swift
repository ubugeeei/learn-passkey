import Foundation

/// The only credential type currently defined by WebAuthn.
public enum PublicKeyCredentialType: String, Codable, Sendable {
  case publicKey = "public-key"
}

/// Hints describing how a client may communicate with an authenticator.
///
/// A relying party must treat transports as routing hints, not proof of an
/// authenticator's security properties.
public enum AuthenticatorTransport: String, Codable, Sendable {
  case ble
  case hybrid
  case internalTransport = "internal"
  case nfc
  case smartCard = "smart-card"
  case usb
}

/// Identifies an existing credential in `allowCredentials` or
/// `excludeCredentials` without exposing its public key.
public struct PublicKeyCredentialDescriptor: Codable, Equatable, Sendable {
  public let type: PublicKeyCredentialType
  public let id: String
  public let transports: [AuthenticatorTransport]?

  public init(
    type: PublicKeyCredentialType = .publicKey,
    id: String,
    transports: [AuthenticatorTransport]? = nil
  ) {
    self.type = type
    self.id = id
    self.transports = transports
  }
}

/// The relying party identity shown to the user during registration.
public struct PublicKeyCredentialRP: Codable, Equatable, Sendable {
  public let id: String
  public let name: String

  public init(id: String, name: String) {
    self.id = id
    self.name = name
  }
}

/// Account data passed to the authenticator during registration.
///
/// `id` is an unpadded Base64url-encoded opaque user handle. It must not be an
/// email address or another cross-service identifier.
public struct PublicKeyCredentialUser: Codable, Equatable, Sendable {
  public let id: String
  public let name: String
  public let displayName: String

  public init(id: String, name: String, displayName: String) {
    self.id = id
    self.name = name
    self.displayName = displayName
  }
}

/// A credential type and COSE algorithm pair accepted by the RP.
public struct PublicKeyCredentialParameters: Codable, Equatable, Sendable {
  public let type: PublicKeyCredentialType
  public let alg: Int

  public init(type: PublicKeyCredentialType = .publicKey, alg: Int) {
    self.type = type
    self.alg = alg
  }
}

/// The RP's discoverable-credential requirement.
public enum ResidentKeyRequirement: String, Codable, Sendable {
  case discouraged
  case preferred
  case required
}

/// The RP's policy for authenticator-local user verification.
public enum UserVerificationRequirement: String, Codable, Sendable {
  case discouraged
  case preferred
  case required
}

/// How much authenticator attestation information the client should return.
public enum AttestationConveyancePreference: String, Codable, Sendable {
  case direct
  case enterprise
  case indirect
  case none
}

/// Registration policy that influences which authenticators are eligible.
public struct AuthenticatorSelectionCriteria: Codable, Equatable, Sendable {
  public let residentKey: ResidentKeyRequirement
  public let userVerification: UserVerificationRequirement

  public init(
    residentKey: ResidentKeyRequirement,
    userVerification: UserVerificationRequirement
  ) {
    self.residentKey = residentKey
    self.userVerification = userVerification
  }
}

/// Server-generated inputs for one registration ceremony.
///
/// The challenge is single-use and expires with the enclosing `ceremonyID`.
public struct PublicKeyCredentialCreationOptions: Codable, Equatable, Sendable {
  public let rp: PublicKeyCredentialRP
  public let user: PublicKeyCredentialUser
  public let challenge: String
  public let pubKeyCredParams: [PublicKeyCredentialParameters]
  public let timeout: Int
  public let excludeCredentials: [PublicKeyCredentialDescriptor]
  public let authenticatorSelection: AuthenticatorSelectionCriteria
  public let attestation: AttestationConveyancePreference

  public init(
    rp: PublicKeyCredentialRP,
    user: PublicKeyCredentialUser,
    challenge: String,
    pubKeyCredParams: [PublicKeyCredentialParameters],
    timeout: Int,
    excludeCredentials: [PublicKeyCredentialDescriptor],
    authenticatorSelection: AuthenticatorSelectionCriteria,
    attestation: AttestationConveyancePreference
  ) {
    self.rp = rp
    self.user = user
    self.challenge = challenge
    self.pubKeyCredParams = pubKeyCredParams
    self.timeout = timeout
    self.excludeCredentials = excludeCredentials
    self.authenticatorSelection = authenticatorSelection
    self.attestation = attestation
  }
}

/// Server-generated inputs for one authentication ceremony.
public struct PublicKeyCredentialRequestOptions: Codable, Equatable, Sendable {
  public let challenge: String
  public let timeout: Int
  public let rpId: String
  public let allowCredentials: [PublicKeyCredentialDescriptor]
  public let userVerification: UserVerificationRequirement

  public init(
    challenge: String,
    timeout: Int,
    rpId: String,
    allowCredentials: [PublicKeyCredentialDescriptor],
    userVerification: UserVerificationRequirement
  ) {
    self.challenge = challenge
    self.timeout = timeout
    self.rpId = rpId
    self.allowCredentials = allowCredentials
    self.userVerification = userVerification
  }
}

/// Registration options plus the opaque server-side ceremony lookup key.
public struct RegistrationOptionsResponse: Codable, Equatable, Sendable {
  public let ceremonyID: String
  public let publicKey: PublicKeyCredentialCreationOptions

  public init(ceremonyID: String, publicKey: PublicKeyCredentialCreationOptions) {
    self.ceremonyID = ceremonyID
    self.publicKey = publicKey
  }
}

/// Authentication options plus the opaque server-side ceremony lookup key.
public struct AuthenticationOptionsResponse: Codable, Equatable, Sendable {
  public let ceremonyID: String
  public let publicKey: PublicKeyCredentialRequestOptions

  public init(ceremonyID: String, publicKey: PublicKeyCredentialRequestOptions) {
    self.ceremonyID = ceremonyID
    self.publicKey = publicKey
  }
}

/// User-supplied labels used to begin first-credential account creation.
public struct BeginRegistrationRequest: Codable, Equatable, Sendable {
  public let username: String
  public let displayName: String

  public init(username: String, displayName: String) {
    self.username = username
    self.displayName = displayName
  }
}

/// An optional username hint for authentication.
///
/// `nil` selects the discoverable, username-less Passkey flow.
public struct BeginAuthenticationRequest: Codable, Equatable, Sendable {
  public let username: String?

  public init(username: String? = nil) {
    self.username = username
  }
}

/// Base64url-encoded raw bytes returned by a registration authorization.
public struct RegistrationCredentialResponse: Codable, Equatable, Sendable {
  public let clientDataJSON: String
  public let attestationObject: String

  public init(clientDataJSON: String, attestationObject: String) {
    self.clientDataJSON = clientDataJSON
    self.attestationObject = attestationObject
  }
}

/// The public-key credential returned to the RP after OS authorization.
public struct CompleteRegistrationRequest: Codable, Equatable, Sendable {
  public let ceremonyID: String
  public let id: String
  public let rawId: String
  public let type: PublicKeyCredentialType
  public let response: RegistrationCredentialResponse

  public init(
    ceremonyID: String,
    id: String,
    rawId: String,
    type: PublicKeyCredentialType,
    response: RegistrationCredentialResponse
  ) {
    self.ceremonyID = ceremonyID
    self.id = id
    self.rawId = rawId
    self.type = type
    self.response = response
  }
}

/// Base64url-encoded raw assertion fields returned by the authenticator.
public struct AuthenticationCredentialResponse: Codable, Equatable, Sendable {
  public let clientDataJSON: String
  public let authenticatorData: String
  public let signature: String
  public let userHandle: String?

  public init(
    clientDataJSON: String,
    authenticatorData: String,
    signature: String,
    userHandle: String?
  ) {
    self.clientDataJSON = clientDataJSON
    self.authenticatorData = authenticatorData
    self.signature = signature
    self.userHandle = userHandle
  }
}

/// The assertion returned to the RP for cryptographic verification.
public struct CompleteAuthenticationRequest: Codable, Equatable, Sendable {
  public let ceremonyID: String
  public let id: String
  public let rawId: String
  public let type: PublicKeyCredentialType
  public let response: AuthenticationCredentialResponse

  public init(
    ceremonyID: String,
    id: String,
    rawId: String,
    type: PublicKeyCredentialType,
    response: AuthenticationCredentialResponse
  ) {
    self.ceremonyID = ceremonyID
    self.id = id
    self.rawId = rawId
    self.type = type
    self.response = response
  }
}

/// Non-sensitive account information returned to an authenticated client.
public struct UserSummaryResponse: Codable, Equatable, Sendable {
  public let id: String
  public let username: String
  public let displayName: String

  public init(id: String, username: String, displayName: String) {
    self.id = id
    self.username = username
    self.displayName = displayName
  }
}

/// Confirms that the RP atomically stored an account and its first credential.
public struct RegistrationResultResponse: Codable, Equatable, Sendable {
  public let user: UserSummaryResponse
  public let credentialID: String

  public init(user: UserSummaryResponse, credentialID: String) {
    self.user = user
    self.credentialID = credentialID
  }
}

/// A verified account and the separate application session it authorized.
public struct AuthenticationResultResponse: Codable, Equatable, Sendable {
  public let user: UserSummaryResponse
  public let sessionToken: String
  public let expiresAt: Date

  public init(user: UserSummaryResponse, sessionToken: String, expiresAt: Date) {
    self.user = user
    self.sessionToken = sessionToken
    self.expiresAt = expiresAt
  }
}

/// Public, user-visible metadata for one registered Passkey.
public struct CredentialSummaryResponse: Codable, Equatable, Identifiable, Sendable {
  public let id: String
  public let createdAt: Date
  public let lastUsedAt: Date?
  public let backupEligible: Bool
  public let backupState: Bool

  public init(
    id: String,
    createdAt: Date,
    lastUsedAt: Date?,
    backupEligible: Bool,
    backupState: Bool
  ) {
    self.id = id
    self.createdAt = createdAt
    self.lastUsedAt = lastUsedAt
    self.backupEligible = backupEligible
    self.backupState = backupState
  }
}

/// Collection envelope used by the credential-management screen.
public struct CredentialListResponse: Codable, Equatable, Sendable {
  public let credentials: [CredentialSummaryResponse]

  public init(credentials: [CredentialSummaryResponse]) {
    self.credentials = credentials
  }
}
