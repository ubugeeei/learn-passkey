import Foundation
import PasskeyCore
import PasskeyServer

/// Maps the lab's HTTP routes to domain services and safe public errors.
///
/// Cryptographic failures are intentionally collapsed at this boundary. Exact
/// reasons remain available to tests and internal logs but must not become an
/// attacker oracle or expose account state to an unauthenticated client.
public final class PasskeyAPI: Sendable {
  public static let maximumBodyBytes = 64 * 1024

  private let passkeys: PasskeyService
  private let sessions: SessionManager
  private let appleApplicationID: String

  public init(
    passkeys: PasskeyService,
    sessions: SessionManager,
    appleApplicationID: String
  ) {
    self.passkeys = passkeys
    self.sessions = sessions
    self.appleApplicationID = appleApplicationID
  }

  /// Handles one complete request with a hard body limit and no shared decoder
  /// state. Every response includes a request ID and `Cache-Control: no-store`.
  public func handle(_ request: HTTPRequestData) async -> HTTPResponseData {
    do {
      guard request.body.count <= Self.maximumBodyBytes else {
        return error(
          status: 413,
          code: "body_too_large",
          message: "The request body is too large.",
          requestID: request.requestID
        )
      }

      switch (request.method, request.path) {
      case ("GET", "/healthz"):
        return try json(status: 200, HealthResponse(status: "ok"), requestID: request.requestID)

      case ("GET", "/.well-known/apple-app-site-association"):
        return try json(
          status: 200,
          AppleAppSiteAssociation(
            webcredentials: .init(apps: [appleApplicationID])
          ),
          requestID: request.requestID
        )

      case ("POST", "/v1/passkeys/registration/options"):
        let body: BeginRegistrationRequest = try decodeJSON(request)
        return try json(
          status: 200,
          await passkeys.beginRegistration(
            username: body.username,
            displayName: body.displayName
          ),
          requestID: request.requestID
        )

      case ("POST", "/v1/passkeys/registration/complete"):
        let body: CompleteRegistrationRequest = try decodeJSON(request)
        let result = try await passkeys.completeRegistration(body)
        return try json(
          status: 201,
          RegistrationResultResponse(
            user: userResponse(result.user),
            credentialID: Base64URL.encode(result.credential.id)
          ),
          requestID: request.requestID
        )

      case ("POST", "/v1/passkeys/authentication/options"):
        let body: BeginAuthenticationRequest = try decodeJSON(request)
        return try json(
          status: 200,
          await passkeys.beginAuthentication(username: body.username),
          requestID: request.requestID
        )

      case ("POST", "/v1/passkeys/authentication/complete"):
        let body: CompleteAuthenticationRequest = try decodeJSON(request)
        let result = try await passkeys.completeAuthentication(body)
        let session = try await sessions.issue(userID: result.user.id)
        return try json(
          status: 200,
          AuthenticationResultResponse(
            user: userResponse(result.user),
            sessionToken: session.token,
            expiresAt: session.expiresAt
          ),
          requestID: request.requestID
        )

      case ("GET", "/v1/me"):
        let user = try await authenticatedUser(request)
        return try json(
          status: 200,
          userResponse(user),
          requestID: request.requestID
        )

      case ("GET", "/v1/passkeys"):
        let userID = try await authenticatedUserID(request)
        let credentials = try await passkeys.credentials(userID: userID)
        return try json(
          status: 200,
          CredentialListResponse(credentials: credentials.map(credentialResponse)),
          requestID: request.requestID
        )

      case ("POST", "/v1/passkeys/addition/options"):
        let userID = try await recentlyAuthenticatedUserID(request)
        return try json(
          status: 200,
          await passkeys.beginCredentialAddition(userID: userID),
          requestID: request.requestID
        )

      case ("POST", "/v1/passkeys/addition/complete"):
        let userID = try await recentlyAuthenticatedUserID(request)
        let body: CompleteRegistrationRequest = try decodeJSON(request)
        let credential = try await passkeys.completeCredentialAddition(body, userID: userID)
        return try json(
          status: 201,
          credentialResponse(credential),
          requestID: request.requestID
        )

      case ("POST", "/v1/session/logout"):
        let token = try bearerToken(request)
        _ = try await sessions.authenticate(token: token)
        try await sessions.revoke(token: token)
        return HTTPResponseData(
          status: 204,
          headers: responseHeaders(requestID: request.requestID)
        )

      default:
        if request.method == "DELETE",
          let encodedID = credentialIDPathComponent(request.path)
        {
          let userID = try await recentlyAuthenticatedUserID(request)
          let credentialID: Data
          do {
            credentialID = try Base64URL.decode(encodedID)
          } catch {
            throw APIInputError.invalidCredentialID
          }
          try await passkeys.removeCredential(id: credentialID, userID: userID)
          try await sessions.revokeAll(userID: userID)
          return HTTPResponseData(
            status: 204,
            headers: responseHeaders(requestID: request.requestID)
          )
        }
        return error(
          status: 404,
          code: "not_found",
          message: "The requested endpoint does not exist.",
          requestID: request.requestID
        )
      }
    } catch {
      return map(error: error, requestID: request.requestID)
    }
  }

  private func authenticatedUser(_ request: HTTPRequestData) async throws -> UserAccount {
    let userID = try await authenticatedUserID(request)
    guard let user = try await passkeys.repository.user(id: userID) else {
      throw SessionManagerError.invalidSession
    }
    return user
  }

  private func authenticatedUserID(_ request: HTTPRequestData) async throws -> UUID {
    try await sessions.authenticate(token: bearerToken(request))
  }

  private func recentlyAuthenticatedUserID(_ request: HTTPRequestData) async throws -> UUID {
    try await sessions.authenticateRecently(
      token: bearerToken(request),
      maximumAge: 5 * 60
    )
  }

  private func credentialIDPathComponent(_ path: String) -> String? {
    let prefix = "/v1/passkeys/"
    guard path.hasPrefix(prefix) else { return nil }
    let component = String(path.dropFirst(prefix.count))
    guard !component.isEmpty, !component.contains("/") else { return nil }
    return component
  }

  private func bearerToken(_ request: HTTPRequestData) throws -> String {
    guard let value = request.headers["authorization"],
      value.hasPrefix("Bearer "),
      value.count > "Bearer ".count
    else {
      throw SessionManagerError.invalidSession
    }
    return String(value.dropFirst("Bearer ".count))
  }

  private func decodeJSON<Value: Decodable>(_ request: HTTPRequestData) throws -> Value {
    guard request.headers["content-type"]?.lowercased().hasPrefix("application/json") == true else {
      throw APIInputError.unsupportedContentType
    }
    guard !request.body.isEmpty else {
      throw APIInputError.emptyBody
    }
    return try JSONDecoder().decode(Value.self, from: request.body)
  }

  private func json<Value: Encodable>(
    status: Int,
    _ value: Value,
    requestID: String
  ) throws -> HTTPResponseData {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    encoder.outputFormatting = [.sortedKeys]
    return try HTTPResponseData(
      status: status,
      headers: responseHeaders(requestID: requestID),
      body: encoder.encode(value)
    )
  }

  private func error(
    status: Int,
    code: String,
    message: String,
    requestID: String
  ) -> HTTPResponseData {
    (try? json(
      status: status,
      APIErrorResponse(code: code, message: message, requestID: requestID),
      requestID: requestID
    )) ?? HTTPResponseData(status: 500)
  }

  private func map(error caught: Error, requestID: String) -> HTTPResponseData {
    switch caught {
    case PasskeyServiceError.usernameAlreadyExists,
      PasskeyRepositoryError.usernameAlreadyExists:
      return error(
        status: 409,
        code: "username_unavailable",
        message: "The username is unavailable.",
        requestID: requestID
      )
    case is APIInputError, is DecodingError,
      PasskeyServiceError.invalidUsername,
      PasskeyServiceError.invalidDisplayName,
      PasskeyServiceError.malformedBase64URL,
      PasskeyServiceError.credentialIDMismatch:
      return error(
        status: 400,
        code: "invalid_request",
        message: "The request is invalid.",
        requestID: requestID
      )
    case SessionManagerError.recentAuthenticationRequired:
      return error(
        status: 403,
        code: "recent_authentication_required",
        message: "Sign in again before changing Passkeys.",
        requestID: requestID
      )
    case PasskeyRepositoryError.lastCredentialRemovalNotAllowed:
      return error(
        status: 409,
        code: "last_credential",
        message: "The last Passkey cannot be removed.",
        requestID: requestID
      )
    case PasskeyRepositoryError.credentialNotFound:
      return error(
        status: 404,
        code: "credential_not_found",
        message: "The Passkey does not exist.",
        requestID: requestID
      )
    case is CeremonyStoreError:
      return error(
        status: 400,
        code: "invalid_ceremony",
        message: "The ceremony is invalid or expired.",
        requestID: requestID
      )
    case is RegistrationVerificationError:
      return error(
        status: 400,
        code: "invalid_registration",
        message: "Passkey registration could not be verified.",
        requestID: requestID
      )
    case is AuthenticationVerificationError,
      is SessionManagerError,
      PasskeyServiceError.credentialNotFound,
      PasskeyServiceError.userMismatch:
      return error(
        status: 401,
        code: "unauthorized",
        message: "Authentication failed.",
        requestID: requestID
      )
    default:
      print("request_id=\(requestID) unhandled_error=\(String(reflecting: caught))")
      return error(
        status: 500,
        code: "internal_error",
        message: "An internal error occurred.",
        requestID: requestID
      )
    }
  }

  private func responseHeaders(requestID: String) -> [String: String] {
    [
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "x-request-id": requestID,
    ]
  }

  private func userResponse(_ user: UserAccount) -> UserSummaryResponse {
    UserSummaryResponse(
      id: user.id.uuidString,
      username: user.username,
      displayName: user.displayName
    )
  }

  private func credentialResponse(_ credential: CredentialRecord) -> CredentialSummaryResponse {
    CredentialSummaryResponse(
      id: Base64URL.encode(credential.id),
      createdAt: credential.createdAt,
      lastUsedAt: credential.lastUsedAt,
      backupEligible: credential.backupEligible,
      backupState: credential.backupState
    )
  }
}

private enum APIInputError: Error {
  case unsupportedContentType
  case emptyBody
  case invalidCredentialID
}

private struct HealthResponse: Codable {
  let status: String
}

private struct AppleAppSiteAssociation: Codable {
  struct WebCredentials: Codable {
    let apps: [String]
  }

  let webcredentials: WebCredentials
}
