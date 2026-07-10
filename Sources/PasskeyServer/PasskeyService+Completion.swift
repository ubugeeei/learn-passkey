import Foundation
import PasskeyCore

/// Domain objects committed by a verified registration.
public struct RegistrationCompletionResult: Equatable, Sendable {
  public let user: UserAccount
  public let credential: CredentialRecord

  public init(user: UserAccount, credential: CredentialRecord) {
    self.user = user
    self.credential = credential
  }
}

/// Updated domain objects produced by a verified assertion.
public struct AuthenticationCompletionResult: Equatable, Sendable {
  public let user: UserAccount
  public let credential: CredentialRecord

  public init(user: UserAccount, credential: CredentialRecord) {
    self.user = user
    self.credential = credential
  }
}

extension PasskeyService {
  /// Consumes a registration challenge, verifies every RP binding, and
  /// atomically creates the account and its first credential.
  public func completeRegistration(
    _ request: CompleteRegistrationRequest
  ) async throws -> RegistrationCompletionResult {
    let state = try await ceremonies.consume(id: request.ceremonyID, at: currentDate())
    guard case .registration(let pending) = state.purpose else {
      throw PasskeyServiceError.wrongCeremonyType
    }
    guard request.id == request.rawId else {
      throw PasskeyServiceError.credentialIDMismatch
    }

    let input = try RegistrationVerificationInput(
      credentialID: decodeBase64URL(request.rawId, field: "rawId"),
      clientDataJSON: decodeBase64URL(request.response.clientDataJSON, field: "clientDataJSON"),
      attestationObject: decodeBase64URL(
        request.response.attestationObject,
        field: "attestationObject"
      )
    )
    let material = try RegistrationVerifier.verify(
      input,
      expecting: RegistrationExpectation(
        challenge: state.challenge,
        rpID: configuration.id,
        allowedOrigins: configuration.allowedOrigins,
        requireUserVerification: configuration.userVerification == .required
      )
    )

    let credential = CredentialRecord(
      id: material.id,
      userID: pending.user.id,
      userHandle: pending.user.userHandle,
      publicKey: material.publicKey,
      rawPublicKey: material.rawPublicKey,
      aaguid: material.aaguid,
      signCount: material.signCount,
      backupEligible: material.backupEligible,
      backupState: material.backupState,
      createdAt: currentDate()
    )
    try await repository.create(user: pending.user, credential: credential)
    return RegistrationCompletionResult(user: pending.user, credential: credential)
  }

  /// Consumes an authentication challenge, verifies the ES256 assertion, and
  /// updates counter/backup metadata before returning the account.
  ///
  /// Application session issuance deliberately happens outside this method.
  public func completeAuthentication(
    _ request: CompleteAuthenticationRequest
  ) async throws -> AuthenticationCompletionResult {
    let usedAt = currentDate()
    let state = try await ceremonies.consume(id: request.ceremonyID, at: usedAt)
    guard case .authentication(let expectedUserID, let requireUserHandle) = state.purpose else {
      throw PasskeyServiceError.wrongCeremonyType
    }
    guard request.id == request.rawId else {
      throw PasskeyServiceError.credentialIDMismatch
    }

    let credentialID = try decodeBase64URL(request.rawId, field: "rawId")
    guard let credential = try await repository.credential(id: credentialID) else {
      throw PasskeyServiceError.credentialNotFound
    }
    if let expectedUserID, credential.userID != expectedUserID {
      throw PasskeyServiceError.userMismatch
    }

    let input = try AuthenticationVerificationInput(
      credentialID: credentialID,
      clientDataJSON: decodeBase64URL(request.response.clientDataJSON, field: "clientDataJSON"),
      authenticatorData: decodeBase64URL(
        request.response.authenticatorData,
        field: "authenticatorData"
      ),
      signature: decodeBase64URL(request.response.signature, field: "signature"),
      userHandle: request.response.userHandle.map {
        try decodeBase64URL($0, field: "userHandle")
      }
    )
    let verification = try AuthenticationVerifier.verify(
      input,
      credential: credential,
      expecting: AuthenticationExpectation(
        challenge: state.challenge,
        rpID: configuration.id,
        allowedOrigins: configuration.allowedOrigins,
        requireUserVerification: configuration.userVerification == .required,
        requireUserHandle: requireUserHandle
      )
    )

    try await repository.updateAfterAuthentication(
      credentialID: credential.id,
      signCount: verification.signCount,
      backupState: verification.backupState,
      usedAt: usedAt
    )
    guard let user = try await repository.user(id: credential.userID),
      let updatedCredential = try await repository.credential(id: credential.id)
    else {
      throw PasskeyServiceError.userMismatch
    }
    return AuthenticationCompletionResult(user: user, credential: updatedCredential)
  }

  private func decodeBase64URL(_ value: String, field: String) throws -> Data {
    do {
      return try Base64URL.decode(value)
    } catch {
      throw PasskeyServiceError.malformedBase64URL(field: field)
    }
  }
}
