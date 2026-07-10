import Foundation
import PasskeyCore

public struct AuthenticationVerificationInput: Equatable, Sendable {
  public let credentialID: Data
  public let clientDataJSON: Data
  public let authenticatorData: Data
  public let signature: Data
  public let userHandle: Data?

  public init(
    credentialID: Data,
    clientDataJSON: Data,
    authenticatorData: Data,
    signature: Data,
    userHandle: Data?
  ) {
    self.credentialID = credentialID
    self.clientDataJSON = clientDataJSON
    self.authenticatorData = authenticatorData
    self.signature = signature
    self.userHandle = userHandle
  }
}

public struct AuthenticationExpectation: Equatable, Sendable {
  public let challenge: Data
  public let rpID: String
  public let allowedOrigins: Set<String>
  public let requireUserVerification: Bool
  public let requireUserHandle: Bool

  public init(
    challenge: Data,
    rpID: String,
    allowedOrigins: Set<String>,
    requireUserVerification: Bool,
    requireUserHandle: Bool
  ) {
    self.challenge = challenge
    self.rpID = rpID
    self.allowedOrigins = allowedOrigins
    self.requireUserVerification = requireUserVerification
    self.requireUserHandle = requireUserHandle
  }
}

public struct AuthenticationVerificationResult: Equatable, Sendable {
  public let signCount: UInt32
  public let backupState: Bool

  public init(signCount: UInt32, backupState: Bool) {
    self.signCount = signCount
    self.backupState = backupState
  }
}

public enum AuthenticationVerifier {
  public static func verify(
    _ input: AuthenticationVerificationInput,
    credential: CredentialRecord,
    expecting expectation: AuthenticationExpectation
  ) throws -> AuthenticationVerificationResult {
    guard input.credentialID.constantTimeEquals(credential.id) else {
      throw AuthenticationVerificationError.credentialIDMismatch
    }

    do {
      _ = try ClientDataValidator.validate(
        input.clientDataJSON,
        expectedType: .get,
        expectedChallenge: expectation.challenge,
        allowedOrigins: expectation.allowedOrigins
      )
    } catch let error as ClientDataValidationError {
      throw AuthenticationVerificationError.clientData(error)
    }

    let authData: AuthenticatorData
    do {
      authData = try AuthenticatorData(rawBytes: input.authenticatorData)
    } catch {
      throw AuthenticationVerificationError.malformedAuthenticatorData
    }

    let expectedRPIDHash = WebAuthnCrypto.sha256(Data(expectation.rpID.utf8))
    guard authData.rpIDHash.constantTimeEquals(expectedRPIDHash) else {
      throw AuthenticationVerificationError.rpIDHashMismatch
    }
    guard authData.flags.contains(.userPresent) else {
      throw AuthenticationVerificationError.userPresenceRequired
    }
    if expectation.requireUserVerification,
      !authData.flags.contains(.userVerified)
    {
      throw AuthenticationVerificationError.userVerificationRequired
    }
    guard !authData.flags.contains(.attestedCredentialData) else {
      throw AuthenticationVerificationError.unexpectedAttestedCredentialData
    }
    guard authData.flags.contains(.backupEligible) == credential.backupEligible else {
      throw AuthenticationVerificationError.backupEligibilityChanged
    }

    if expectation.requireUserHandle, input.userHandle == nil {
      throw AuthenticationVerificationError.userHandleRequired
    }
    if let userHandle = input.userHandle,
      !userHandle.constantTimeEquals(credential.userHandle)
    {
      throw AuthenticationVerificationError.userHandleMismatch
    }

    let clientDataHash = WebAuthnCrypto.sha256(input.clientDataJSON)
    let signedData = input.authenticatorData + clientDataHash
    let signatureIsValid: Bool
    do {
      signatureIsValid = try WebAuthnCrypto.verifyES256(
        signatureDER: input.signature,
        signedData: signedData,
        publicKeyX963: credential.publicKey.x963Representation
      )
    } catch {
      throw AuthenticationVerificationError.malformedPublicKeyOrSignature
    }
    guard signatureIsValid else {
      throw AuthenticationVerificationError.invalidSignature
    }

    if credential.signCount != 0 || authData.signCount != 0 {
      guard authData.signCount > credential.signCount else {
        throw AuthenticationVerificationError.signatureCounterDidNotAdvance(
          stored: credential.signCount,
          received: authData.signCount
        )
      }
    }

    return AuthenticationVerificationResult(
      signCount: authData.signCount,
      backupState: authData.flags.contains(.backupState)
    )
  }
}

public enum AuthenticationVerificationError: Error, Equatable, Sendable {
  case credentialIDMismatch
  case clientData(ClientDataValidationError)
  case malformedAuthenticatorData
  case rpIDHashMismatch
  case userPresenceRequired
  case userVerificationRequired
  case unexpectedAttestedCredentialData
  case backupEligibilityChanged
  case userHandleRequired
  case userHandleMismatch
  case malformedPublicKeyOrSignature
  case invalidSignature
  case signatureCounterDidNotAdvance(stored: UInt32, received: UInt32)
}
