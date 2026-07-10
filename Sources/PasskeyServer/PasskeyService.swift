import Foundation
import PasskeyCore

public final class PasskeyService: Sendable {
  public let configuration: RelyingPartyConfiguration
  public let repository: any PasskeyRepository
  public let ceremonies: any CeremonyStore

  private let now: @Sendable () -> Date
  private let randomBytes: @Sendable (Int) throws -> Data

  public init(
    configuration: RelyingPartyConfiguration,
    repository: any PasskeyRepository,
    ceremonies: any CeremonyStore,
    now: @escaping @Sendable () -> Date = { Date() },
    randomBytes: @escaping @Sendable (Int) throws -> Data = { try SecureRandom.bytes(count: $0) }
  ) {
    self.configuration = configuration
    self.repository = repository
    self.ceremonies = ceremonies
    self.now = now
    self.randomBytes = randomBytes
  }

  public func beginRegistration(
    username: String,
    displayName: String
  ) async throws -> RegistrationOptionsResponse {
    let username = try Self.validatedUsername(username)
    let displayName = try Self.validatedDisplayName(displayName)
    guard try await repository.user(named: username) == nil else {
      throw PasskeyServiceError.usernameAlreadyExists
    }

    let issuedAt = now()
    let user = UserAccount(
      id: UUID(),
      userHandle: try randomBytes(32),
      username: username,
      displayName: displayName,
      createdAt: issuedAt
    )
    let state = try makeCeremony(
      purpose: .registration(PendingRegistration(user: user)),
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
        excludeCredentials: [],
        authenticatorSelection: AuthenticatorSelectionCriteria(
          residentKey: .required,
          userVerification: configuration.userVerification
        ),
        attestation: .none
      )
    )
  }

  public func beginAuthentication(
    username: String? = nil
  ) async throws -> AuthenticationOptionsResponse {
    let selectedUser: UserAccount?
    if let username {
      selectedUser = try await repository.user(named: Self.validatedUsername(username))
    } else {
      selectedUser = nil
    }

    let allowCredentials: [PublicKeyCredentialDescriptor]
    if let selectedUser {
      allowCredentials = try await repository.credentials(userID: selectedUser.id).map {
        PublicKeyCredentialDescriptor(id: Base64URL.encode($0.id))
      }
    } else {
      allowCredentials = []
    }

    let issuedAt = now()
    let state = try makeCeremony(
      purpose: .authentication(
        expectedUserID: selectedUser?.id,
        requireUserHandle: selectedUser == nil
      ),
      issuedAt: issuedAt
    )
    try await ceremonies.save(state)

    return AuthenticationOptionsResponse(
      ceremonyID: state.id,
      publicKey: PublicKeyCredentialRequestOptions(
        challenge: Base64URL.encode(state.challenge),
        timeout: configuration.requestTimeoutMilliseconds,
        rpId: configuration.id,
        allowCredentials: allowCredentials,
        userVerification: configuration.userVerification
      )
    )
  }

  private func makeCeremony(purpose: CeremonyPurpose, issuedAt: Date) throws -> CeremonyState {
    CeremonyState(
      id: Base64URL.encode(try randomBytes(24)),
      challenge: try randomBytes(32),
      purpose: purpose,
      expiresAt: issuedAt.addingTimeInterval(configuration.ceremonyTimeToLive)
    )
  }

  private static func validatedUsername(_ value: String) throws -> String {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty, trimmed.utf8.count <= 128 else {
      throw PasskeyServiceError.invalidUsername
    }
    return trimmed
  }

  private static func validatedDisplayName(_ value: String) throws -> String {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty, trimmed.utf8.count <= 128 else {
      throw PasskeyServiceError.invalidDisplayName
    }
    return trimmed
  }
}

public enum PasskeyServiceError: Error, Equatable, Sendable {
  case invalidUsername
  case invalidDisplayName
  case usernameAlreadyExists
  case wrongCeremonyType
  case credentialNotFound
  case userMismatch
}
