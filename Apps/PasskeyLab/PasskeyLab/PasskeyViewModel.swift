import Observation
import PasskeyClient
import PasskeyCore

/// Coordinates the application workflow without owning cryptographic state.
///
/// The RP client, OS authorization adapter, and view state are separate so the
/// UI never needs to inspect WebAuthn byte structures. The private key remains
/// behind AuthenticationServices for the entire lifetime of this object.
@MainActor
@Observable
final class PasskeyViewModel {
  enum Phase: Equatable {
    case signedOut
    case registering
    case authenticating
    case signedIn(UserSummaryResponse)
    case failed(String)

    var isBusy: Bool {
      self == .registering || self == .authenticating
    }
  }

  var username = "alice@example.com"
  var displayName = "Alice"
  private(set) var phase: Phase = .signedOut

  private let api: PasskeyAPIClient
  private let authorization: PasskeyAuthorizationService
  private var sessionToken: String?

  init(api: PasskeyAPIClient, authorization: PasskeyAuthorizationService) {
    self.api = api
    self.authorization = authorization
  }

  /// Creates a new account only after the server has verified the complete
  /// registration ceremony. A failed sheet or verification leaves no account.
  func register() async {
    guard !phase.isBusy else { return }
    phase = .registering
    do {
      let options = try await api.beginRegistration(
        username: username,
        displayName: displayName
      )
      let credential = try await authorization.register(options: options)
      _ = try await api.completeRegistration(credential)
      phase = .signedOut
    } catch {
      phase = .failed(message(for: error))
    }
  }

  /// Performs a discoverable-credential flow, verifies it on the RP, and
  /// retains the resulting application session in memory for this lab.
  func signIn(
    presentation: PasskeyAuthorizationService.Presentation = .modal
  ) async {
    guard !phase.isBusy else { return }
    phase = .authenticating
    do {
      let options = try await api.beginAuthentication()
      let assertion = try await authorization.authenticate(
        options: options,
        presentation: presentation
      )
      let result = try await api.completeAuthentication(assertion)
      sessionToken = result.sessionToken
      phase = .signedIn(result.user)
    } catch {
      phase = .failed(message(for: error))
    }
  }

  /// Revokes the server-side session. It intentionally does not remove the
  /// Passkey credential from iCloud Keychain or the RP account.
  func signOut() async {
    guard let sessionToken else {
      phase = .signedOut
      return
    }
    do {
      try await api.logout(sessionToken: sessionToken)
      self.sessionToken = nil
      phase = .signedOut
    } catch {
      phase = .failed(message(for: error))
    }
  }

  private func message(for error: Error) -> String {
    if let error = error as? PasskeyAPIClientError {
      switch error {
      case .server(_, let code, _, let requestID):
        return [code, requestID].compactMap { $0 }.joined(separator: " | ")
      case .invalidBaseURL:
        return "The API base URL is invalid."
      case .nonHTTPResponse, .invalidResponseBody:
        return "The server returned an invalid response."
      }
    }
    return error.localizedDescription
  }
}
