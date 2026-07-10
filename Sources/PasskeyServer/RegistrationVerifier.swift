import Foundation
import PasskeyCore

/// Untrusted registration response bytes received from a client.
public struct RegistrationVerificationInput: Equatable, Sendable {
  public let credentialID: Data
  public let clientDataJSON: Data
  public let attestationObject: Data

  public init(credentialID: Data, clientDataJSON: Data, attestationObject: Data) {
    self.credentialID = credentialID
    self.clientDataJSON = clientDataJSON
    self.attestationObject = attestationObject
  }
}

/// Trusted RP values retained from registration option generation.
public struct RegistrationExpectation: Equatable, Sendable {
  public let challenge: Data
  public let rpID: String
  public let allowedOrigins: Set<String>
  public let requireUserVerification: Bool

  public init(
    challenge: Data,
    rpID: String,
    allowedOrigins: Set<String>,
    requireUserVerification: Bool
  ) {
    self.challenge = challenge
    self.rpID = rpID
    self.allowedOrigins = allowedOrigins
    self.requireUserVerification = requireUserVerification
  }
}

/// Public credential material extracted only after all checks pass.
public struct RegisteredCredentialMaterial: Equatable, Sendable {
  public let id: Data
  public let publicKey: COSEEC2PublicKey
  public let rawPublicKey: Data
  public let aaguid: Data
  public let signCount: UInt32
  public let backupEligible: Bool
  public let backupState: Bool

  public init(
    id: Data,
    publicKey: COSEEC2PublicKey,
    rawPublicKey: Data,
    aaguid: Data,
    signCount: UInt32,
    backupEligible: Bool,
    backupState: Bool
  ) {
    self.id = id
    self.publicKey = publicKey
    self.rawPublicKey = rawPublicKey
    self.aaguid = aaguid
    self.signCount = signCount
    self.backupEligible = backupEligible
    self.backupState = backupState
  }
}

/// Implements the RP's `none`-attestation ES256 registration policy.
public enum RegistrationVerifier {
  /// Verifies challenge/origin/RP bindings, flags, attestation shape, credential
  /// identity, and the COSE public key before returning storable material.
  public static func verify(
    _ input: RegistrationVerificationInput,
    expecting expectation: RegistrationExpectation
  ) throws -> RegisteredCredentialMaterial {
    guard !input.credentialID.isEmpty, input.credentialID.count <= 1_024 else {
      throw RegistrationVerificationError.invalidCredentialIDLength(input.credentialID.count)
    }

    do {
      _ = try ClientDataValidator.validate(
        input.clientDataJSON,
        expectedType: .create,
        expectedChallenge: expectation.challenge,
        allowedOrigins: expectation.allowedOrigins
      )
    } catch let error as ClientDataValidationError {
      throw RegistrationVerificationError.clientData(error)
    }

    let object: AttestationObject
    do {
      object = try AttestationObject(rawBytes: input.attestationObject)
    } catch {
      throw RegistrationVerificationError.malformedAttestationObject
    }

    guard object.format == "none" else {
      throw RegistrationVerificationError.unsupportedAttestationFormat(object.format)
    }
    guard object.attestationStatement.mapEntries?.isEmpty == true else {
      throw RegistrationVerificationError.nonEmptyNoneAttestationStatement
    }

    let authData = object.authenticatorData
    let expectedRPIDHash = WebAuthnCrypto.sha256(Data(expectation.rpID.utf8))
    guard authData.rpIDHash.constantTimeEquals(expectedRPIDHash) else {
      throw RegistrationVerificationError.rpIDHashMismatch
    }
    guard authData.flags.contains(.userPresent) else {
      throw RegistrationVerificationError.userPresenceRequired
    }
    if expectation.requireUserVerification,
      !authData.flags.contains(.userVerified)
    {
      throw RegistrationVerificationError.userVerificationRequired
    }
    guard let credential = authData.attestedCredential else {
      throw RegistrationVerificationError.missingAttestedCredentialData
    }
    guard credential.credentialID.constantTimeEquals(input.credentialID) else {
      throw RegistrationVerificationError.credentialIDMismatch
    }

    return RegisteredCredentialMaterial(
      id: credential.credentialID,
      publicKey: credential.credentialPublicKey,
      rawPublicKey: credential.rawCredentialPublicKey,
      aaguid: credential.aaguid,
      signCount: authData.signCount,
      backupEligible: authData.flags.contains(.backupEligible),
      backupState: authData.flags.contains(.backupState)
    )
  }
}

/// A specific registration verification failure, useful in tests and internal
/// audit events but mapped to a coarse public API error.
public enum RegistrationVerificationError: Error, Equatable, Sendable {
  case invalidCredentialIDLength(Int)
  case clientData(ClientDataValidationError)
  case malformedAttestationObject
  case unsupportedAttestationFormat(String)
  case nonEmptyNoneAttestationStatement
  case rpIDHashMismatch
  case userPresenceRequired
  case userVerificationRequired
  case missingAttestedCredentialData
  case credentialIDMismatch
}
