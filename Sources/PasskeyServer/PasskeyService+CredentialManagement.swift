import Foundation
import PasskeyCore

extension PasskeyService {
  /// Starts an authenticated ceremony for adding another credential.
  public func beginCredentialAddition(userID: UUID) async throws -> RegistrationOptionsResponse {
    guard let user = try await repository.user(id: userID) else {
      throw PasskeyServiceError.userMismatch
    }
    let existing = try await repository.credentials(userID: userID)
    let issuedAt = currentDate()
    let state = try makeCeremony(
      purpose: .credentialAddition(expectedUserID: userID),
      issuedAt: issuedAt
    )
    try await ceremonies.save(state)

    return RegistrationOptionsResponse(
      ceremonyID: state.id,
      publicKey: PublicKeyCredentialCreationOptions(
        rp: PublicKeyCredentialRP(id: configuration.id, name: configuration.name),
        user: PublicKeyCredentialUser(
          id: Base64URL.encode(user.userHandle),
          name: user.username,
          displayName: user.displayName
        ),
        challenge: Base64URL.encode(state.challenge),
        pubKeyCredParams: [PublicKeyCredentialParameters(alg: -7)],
        timeout: configuration.requestTimeoutMilliseconds,
        excludeCredentials: existing.map {
          PublicKeyCredentialDescriptor(id: Base64URL.encode($0.id))
        },
        authenticatorSelection: AuthenticatorSelectionCriteria(
          residentKey: .required,
          userVerification: configuration.userVerification
        ),
        attestation: .none
      )
    )
  }

  /// Verifies and stores an additional credential for the authenticated account.
  public func completeCredentialAddition(
    _ request: CompleteRegistrationRequest,
    userID: UUID
  ) async throws -> CredentialRecord {
    let state = try await ceremonies.consume(id: request.ceremonyID, at: currentDate())
    guard case .credentialAddition(let expectedUserID) = state.purpose,
      expectedUserID == userID,
      let user = try await repository.user(id: userID)
    else {
      throw PasskeyServiceError.userMismatch
    }
    guard request.id == request.rawId else {
      throw PasskeyServiceError.credentialIDMismatch
    }

    let input = try RegistrationVerificationInput(
      credentialID: decodeCredentialField(request.rawId, name: "rawId"),
      clientDataJSON: decodeCredentialField(
        request.response.clientDataJSON, name: "clientDataJSON"),
      attestationObject: decodeCredentialField(
        request.response.attestationObject,
        name: "attestationObject"
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
      userID: user.id,
      userHandle: user.userHandle,
      publicKey: material.publicKey,
      rawPublicKey: material.rawPublicKey,
      aaguid: material.aaguid,
      signCount: material.signCount,
      backupEligible: material.backupEligible,
      backupState: material.backupState,
      createdAt: currentDate()
    )
    try await repository.add(credential: credential, to: userID)
    return credential
  }

  /// Lists public metadata for credentials owned by one account.
  public func credentials(userID: UUID) async throws -> [CredentialRecord] {
    try await repository.credentials(userID: userID)
  }

  /// Removes one owned credential while preserving at least one sign-in method.
  public func removeCredential(id: Data, userID: UUID) async throws {
    try await repository.removeCredential(id: id, from: userID)
  }

  private func decodeCredentialField(_ value: String, name: String) throws -> Data {
    do {
      return try Base64URL.decode(value)
    } catch {
      throw PasskeyServiceError.malformedBase64URL(field: name)
    }
  }
}
