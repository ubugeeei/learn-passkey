import Foundation
import PasskeyCore

/// A small, typed HTTP client for the relying-party endpoints in this lab.
///
/// This type deliberately does not perform a WebAuthn ceremony. It only moves
/// JSON between the app and the RP server. `PasskeyAuthorizationService` owns
/// the separate trust boundary between the app and AuthenticationServices.
public struct PasskeyAPIClient: Sendable {
  /// An injectable transport used by tests and by applications that need a
  /// customized `URLSession` (for example, certificate pinning experiments).
  public typealias Transport = @Sendable (URLRequest) async throws -> (Data, HTTPURLResponse)

  public let baseURL: URL
  private let transport: Transport

  /// Creates a client backed by the given URL session.
  ///
  /// The base URL must be an HTTPS origin with no path, query, user info, or
  /// fragment. Passkeys bind to a web origin; accepting a looser URL here can
  /// make an app appear to talk to the right RP while using the wrong origin.
  public init(baseURL: URL, session: URLSession = .shared) throws {
    try self.init(baseURL: baseURL) { request in
      let (data, response) = try await session.data(for: request)
      guard let response = response as? HTTPURLResponse else {
        throw PasskeyAPIClientError.nonHTTPResponse
      }
      return (data, response)
    }
  }

  /// Creates a client with an explicit transport.
  ///
  /// This initializer is public so a production app can apply its own
  /// `URLSessionConfiguration`, metrics, or test double without changing the
  /// protocol implementation.
  public init(baseURL: URL, transport: @escaping Transport) throws {
    guard let components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false),
      components.scheme == "https",
      components.host != nil,
      components.user == nil,
      components.password == nil,
      components.query == nil,
      components.fragment == nil,
      components.path.isEmpty || components.path == "/"
    else {
      throw PasskeyAPIClientError.invalidBaseURL
    }
    self.baseURL = baseURL
    self.transport = transport
  }

  /// Starts account creation and returns server-generated registration
  /// options. No account exists until the completion endpoint succeeds.
  public func beginRegistration(
    username: String,
    displayName: String
  ) async throws -> RegistrationOptionsResponse {
    try await post(
      path: "/v1/passkeys/registration/options",
      body: BeginRegistrationRequest(username: username, displayName: displayName)
    )
  }

  /// Sends the exact raw credential bytes returned by AuthenticationServices
  /// to the server. The client must not parse, normalize, or re-encode the
  /// embedded `clientDataJSON` or attestation object.
  public func completeRegistration(
    _ request: CompleteRegistrationRequest
  ) async throws -> RegistrationResultResponse {
    try await post(path: "/v1/passkeys/registration/complete", body: request)
  }

  /// Requests a fresh, single-use authentication challenge.
  ///
  /// Pass `nil` for a discoverable, username-less Passkey flow. A username
  /// may be supplied to constrain the OS chooser to that account's known
  /// credential IDs.
  public func beginAuthentication(
    username: String? = nil
  ) async throws -> AuthenticationOptionsResponse {
    try await post(
      path: "/v1/passkeys/authentication/options",
      body: BeginAuthenticationRequest(username: username)
    )
  }

  /// Verifies an assertion on the server and returns an application session.
  /// The returned bearer is not the Passkey and should be stored and rotated
  /// according to the application's session policy.
  public func completeAuthentication(
    _ request: CompleteAuthenticationRequest
  ) async throws -> AuthenticationResultResponse {
    try await post(path: "/v1/passkeys/authentication/complete", body: request)
  }

  /// Resolves the account associated with a previously issued bearer token.
  public func currentUser(sessionToken: String) async throws -> UserSummaryResponse {
    try await send(
      path: "/v1/me",
      method: "GET",
      body: Optional<BeginAuthenticationRequest>.none,
      sessionToken: sessionToken
    )
  }

  /// Revokes the presented application session. This does not delete the
  /// Passkey from the authenticator or the public key from the RP.
  public func logout(sessionToken: String) async throws {
    _ = try await perform(
      path: "/v1/session/logout",
      method: "POST",
      body: Optional<BeginAuthenticationRequest>.none,
      sessionToken: sessionToken
    )
  }

  private func post<Body: Encodable & Sendable, Response: Decodable & Sendable>(
    path: String,
    body: Body
  ) async throws -> Response {
    try await send(path: path, method: "POST", body: body)
  }

  private func send<Body: Encodable & Sendable, Response: Decodable & Sendable>(
    path: String,
    method: String,
    body: Body?,
    sessionToken: String? = nil
  ) async throws -> Response {
    let data = try await perform(
      path: path,
      method: method,
      body: body,
      sessionToken: sessionToken
    )

    do {
      let decoder = JSONDecoder()
      decoder.dateDecodingStrategy = .iso8601
      return try decoder.decode(Response.self, from: data)
    } catch {
      throw PasskeyAPIClientError.invalidResponseBody
    }
  }

  private func perform<Body: Encodable & Sendable>(
    path: String,
    method: String,
    body: Body?,
    sessionToken: String? = nil
  ) async throws -> Data {
    guard let url = URL(string: path, relativeTo: baseURL) else {
      throw PasskeyAPIClientError.invalidBaseURL
    }
    var request = URLRequest(url: url)
    request.httpMethod = method
    request.setValue("application/json", forHTTPHeaderField: "accept")
    if let body {
      let encoder = JSONEncoder()
      encoder.dateEncodingStrategy = .iso8601
      request.httpBody = try encoder.encode(body)
      request.setValue("application/json", forHTTPHeaderField: "content-type")
    }
    if let sessionToken {
      request.setValue("Bearer \(sessionToken)", forHTTPHeaderField: "authorization")
    }

    let (data, response) = try await transport(request)
    guard (200..<300).contains(response.statusCode) else {
      let envelope = try? JSONDecoder().decode(ServerErrorEnvelope.self, from: data)
      throw PasskeyAPIClientError.server(
        status: response.statusCode,
        code: envelope?.code,
        message: envelope?.message,
        requestID: envelope?.requestID
      )
    }
    return data
  }
}

/// Failures raised before or after the OS-managed Passkey ceremony.
public enum PasskeyAPIClientError: Error, Equatable, Sendable {
  case invalidBaseURL
  case nonHTTPResponse
  case invalidResponseBody
  case server(status: Int, code: String?, message: String?, requestID: String?)
}

private struct ServerErrorEnvelope: Decodable {
  let code: String
  let message: String
  let requestID: String
}
