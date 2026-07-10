import Foundation

public enum PublicKeyCredentialType: String, Codable, Sendable {
  case publicKey = "public-key"
}

public enum AuthenticatorTransport: String, Codable, Sendable {
  case ble
  case hybrid
  case internalTransport = "internal"
  case nfc
  case smartCard = "smart-card"
  case usb
}

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

public struct PublicKeyCredentialRP: Codable, Equatable, Sendable {
  public let id: String
  public let name: String

  public init(id: String, name: String) {
    self.id = id
    self.name = name
  }
}

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

public struct PublicKeyCredentialParameters: Codable, Equatable, Sendable {
  public let type: PublicKeyCredentialType
  public let alg: Int

  public init(type: PublicKeyCredentialType = .publicKey, alg: Int) {
    self.type = type
    self.alg = alg
  }
}

public enum ResidentKeyRequirement: String, Codable, Sendable {
  case discouraged
  case preferred
  case required
}

public enum UserVerificationRequirement: String, Codable, Sendable {
  case discouraged
  case preferred
  case required
}

public enum AttestationConveyancePreference: String, Codable, Sendable {
  case direct
  case enterprise
  case indirect
  case none
}

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

public struct RegistrationOptionsResponse: Codable, Equatable, Sendable {
  public let ceremonyID: String
  public let publicKey: PublicKeyCredentialCreationOptions

  public init(ceremonyID: String, publicKey: PublicKeyCredentialCreationOptions) {
    self.ceremonyID = ceremonyID
    self.publicKey = publicKey
  }
}

public struct AuthenticationOptionsResponse: Codable, Equatable, Sendable {
  public let ceremonyID: String
  public let publicKey: PublicKeyCredentialRequestOptions

  public init(ceremonyID: String, publicKey: PublicKeyCredentialRequestOptions) {
    self.ceremonyID = ceremonyID
    self.publicKey = publicKey
  }
}

public struct BeginRegistrationRequest: Codable, Equatable, Sendable {
  public let username: String
  public let displayName: String

  public init(username: String, displayName: String) {
    self.username = username
    self.displayName = displayName
  }
}

public struct BeginAuthenticationRequest: Codable, Equatable, Sendable {
  public let username: String?

  public init(username: String? = nil) {
    self.username = username
  }
}

public struct RegistrationCredentialResponse: Codable, Equatable, Sendable {
  public let clientDataJSON: String
  public let attestationObject: String

  public init(clientDataJSON: String, attestationObject: String) {
    self.clientDataJSON = clientDataJSON
    self.attestationObject = attestationObject
  }
}

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
