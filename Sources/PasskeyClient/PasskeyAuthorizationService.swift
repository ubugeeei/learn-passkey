import AuthenticationServices
import Foundation
import PasskeyCore

/// Controls the OS-owned Passkey sheet and converts its result into the lab's
/// transport models.
///
/// The service is main-actor isolated because AuthenticationServices delegates
/// and presentation anchors are UI concerns. It never receives a private key or
/// biometric data. It forwards only the public credential response that the OS
/// makes available to the relying party.
@MainActor
public final class PasskeyAuthorizationService: NSObject {
  /// Chooses between the explicit system sheet and AutoFill-assisted UI.
  public enum Presentation: Sendable {
    case modal
    case autoFill
  }

  private let presentationAnchorProvider: @MainActor @Sendable () -> ASPresentationAnchor
  private var controller: ASAuthorizationController?
  private var pending: PendingOperation?

  /// Creates the UI bridge.
  ///
  /// The closure is evaluated when the OS requests a presentation context, so
  /// it should return the current foreground scene's key window.
  public init(
    presentationAnchorProvider: @escaping @MainActor @Sendable () -> ASPresentationAnchor
  ) {
    self.presentationAnchorProvider = presentationAnchorProvider
    super.init()
  }

  /// Presents the system registration sheet using server-provided values.
  ///
  /// `challenge` and `user.id` are decoded as opaque bytes. The RP identifier
  /// is taken from the signed server options, not from editable UI state.
  public func register(
    options: RegistrationOptionsResponse
  ) async throws -> CompleteRegistrationRequest {
    guard pending == nil else { throw PasskeyAuthorizationError.operationInProgress }
    let challenge = try decode(options.publicKey.challenge, field: "challenge")
    let userID = try decode(options.publicKey.user.id, field: "user.id")
    let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
      relyingPartyIdentifier: options.publicKey.rp.id
    )
    let request = provider.createCredentialRegistrationRequest(
      challenge: challenge,
      name: options.publicKey.user.name,
      userID: userID
    )
    request.displayName = options.publicKey.user.displayName
    request.userVerificationPreference = userVerification(
      options.publicKey.authenticatorSelection.userVerification
    )
    request.attestationPreference = .none

    return try await withCheckedThrowingContinuation { continuation in
      pending = .registration(
        ceremonyID: options.ceremonyID,
        continuation: continuation
      )
      perform(request, presentation: .modal)
    }
  }

  /// Presents a Passkey chooser and creates an assertion response.
  ///
  /// AuthenticationServices signs `authenticatorData ||
  /// SHA-256(clientDataJSON)`. The raw values returned here must reach the
  /// server byte-for-byte.
  public func authenticate(
    options: AuthenticationOptionsResponse,
    presentation: Presentation = .modal
  ) async throws -> CompleteAuthenticationRequest {
    guard pending == nil else { throw PasskeyAuthorizationError.operationInProgress }
    let challenge = try decode(options.publicKey.challenge, field: "challenge")
    let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
      relyingPartyIdentifier: options.publicKey.rpId
    )
    let request = provider.createCredentialAssertionRequest(challenge: challenge)
    request.userVerificationPreference = userVerification(options.publicKey.userVerification)
    request.allowedCredentials = try options.publicKey.allowCredentials.map {
      ASAuthorizationPlatformPublicKeyCredentialDescriptor(
        credentialID: try decode($0.id, field: "allowCredentials.id")
      )
    }

    return try await withCheckedThrowingContinuation { continuation in
      pending = .authentication(
        ceremonyID: options.ceremonyID,
        continuation: continuation
      )
      perform(request, presentation: presentation)
    }
  }

  /// Cancels the currently presented OS authorization UI, if any.
  public func cancel() {
    controller?.cancel()
  }

  private func perform(
    _ request: ASAuthorizationRequest,
    presentation: Presentation
  ) {
    let controller = ASAuthorizationController(authorizationRequests: [request])
    controller.delegate = self
    controller.presentationContextProvider = self
    self.controller = controller
    switch presentation {
    case .modal:
      controller.performRequests()
    case .autoFill:
      #if os(iOS)
        controller.performAutoFillAssistedRequests()
      #else
        controller.performRequests()
      #endif
    }
  }

  private func decode(_ value: String, field: String) throws -> Data {
    do {
      return try Base64URL.decode(value)
    } catch {
      throw PasskeyAuthorizationError.malformedServerValue(field: field)
    }
  }

  private func userVerification(
    _ value: UserVerificationRequirement
  ) -> ASAuthorizationPublicKeyCredentialUserVerificationPreference {
    switch value {
    case .required: .required
    case .preferred: .preferred
    case .discouraged: .discouraged
    }
  }

  private func finish() {
    pending = nil
    controller = nil
  }
}

extension PasskeyAuthorizationService: ASAuthorizationControllerDelegate {
  public func authorizationController(
    controller: ASAuthorizationController,
    didCompleteWithAuthorization authorization: ASAuthorization
  ) {
    switch (pending, authorization.credential) {
    case (
      .registration(let ceremonyID, let continuation),
      let credential as ASAuthorizationPlatformPublicKeyCredentialRegistration
    ):
      guard let attestationObject = credential.rawAttestationObject else {
        continuation.resume(throwing: PasskeyAuthorizationError.missingAttestationObject)
        finish()
        return
      }
      let credentialID = Base64URL.encode(credential.credentialID)
      continuation.resume(
        returning: CompleteRegistrationRequest(
          ceremonyID: ceremonyID,
          id: credentialID,
          rawId: credentialID,
          type: .publicKey,
          response: RegistrationCredentialResponse(
            clientDataJSON: Base64URL.encode(credential.rawClientDataJSON),
            attestationObject: Base64URL.encode(attestationObject)
          )
        )
      )
      finish()

    case (
      .authentication(let ceremonyID, let continuation),
      let credential as ASAuthorizationPlatformPublicKeyCredentialAssertion
    ):
      let credentialID = Base64URL.encode(credential.credentialID)
      continuation.resume(
        returning: CompleteAuthenticationRequest(
          ceremonyID: ceremonyID,
          id: credentialID,
          rawId: credentialID,
          type: .publicKey,
          response: AuthenticationCredentialResponse(
            clientDataJSON: Base64URL.encode(credential.rawClientDataJSON),
            authenticatorData: Base64URL.encode(credential.rawAuthenticatorData),
            signature: Base64URL.encode(credential.signature),
            userHandle: Base64URL.encode(credential.userID)
          )
        )
      )
      finish()

    default:
      resumePending(throwing: PasskeyAuthorizationError.unexpectedCredentialType)
    }
  }

  public func authorizationController(
    controller: ASAuthorizationController,
    didCompleteWithError error: Error
  ) {
    resumePending(throwing: error)
  }

  private func resumePending(throwing error: Error) {
    switch pending {
    case .registration(_, let continuation):
      continuation.resume(throwing: error)
    case .authentication(_, let continuation):
      continuation.resume(throwing: error)
    case nil:
      break
    }
    finish()
  }
}

extension PasskeyAuthorizationService: ASAuthorizationControllerPresentationContextProviding {
  public func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor
  {
    presentationAnchorProvider()
  }
}

/// Errors produced by the app-to-AuthenticationServices adapter itself.
public enum PasskeyAuthorizationError: Error, Equatable, Sendable {
  case operationInProgress
  case malformedServerValue(field: String)
  case missingAttestationObject
  case unexpectedCredentialType
}

@MainActor
private enum PendingOperation {
  case registration(
    ceremonyID: String,
    continuation: CheckedContinuation<CompleteRegistrationRequest, any Error>
  )
  case authentication(
    ceremonyID: String,
    continuation: CheckedContinuation<CompleteAuthenticationRequest, any Error>
  )
}
