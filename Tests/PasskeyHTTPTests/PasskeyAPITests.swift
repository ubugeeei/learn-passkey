import Foundation
import PasskeyCore
import PasskeyServer
import Testing

@testable import PasskeyHTTP

@Suite struct PasskeyAPITests {
  @Test func healthResponseHasSecurityHeaders() async throws {
    let api = try makeAPI()

    let response = await api.handle(request(method: "GET", path: "/healthz"))

    #expect(response.status == 200)
    #expect(response.headers["cache-control"] == "no-store")
    #expect(response.headers["x-content-type-options"] == "nosniff")
    #expect(response.headers["x-request-id"] == "test-request")
    #expect(try JSONDecoder().decode(Health.self, from: response.body).status == "ok")
  }

  @Test func servesWebCredentialsAssociationWithoutRedirect() async throws {
    let api = try makeAPI()

    let response = await api.handle(
      request(method: "GET", path: "/.well-known/apple-app-site-association")
    )
    let object = try #require(
      JSONSerialization.jsonObject(with: response.body) as? [String: Any]
    )
    let webcredentials = try #require(object["webcredentials"] as? [String: Any])

    #expect(response.status == 200)
    #expect(webcredentials["apps"] as? [String] == ["TEAMID.com.example.PasskeyLab"])
  }

  @Test func registrationOptionsRouteDecodesAndEncodesSharedModels() async throws {
    let api = try makeAPI()
    let requestBody = try JSONEncoder().encode(
      BeginRegistrationRequest(username: "alice@example.com", displayName: "Alice")
    )

    let response = await api.handle(
      request(
        method: "POST",
        path: "/v1/passkeys/registration/options",
        body: requestBody
      )
    )
    let options = try JSONDecoder().decode(RegistrationOptionsResponse.self, from: response.body)

    #expect(response.status == 200)
    #expect(options.publicKey.rp.id == "passkeys.example.com")
    #expect(options.publicKey.user.name == "alice@example.com")
    #expect(options.publicKey.attestation == .none)
  }

  @Test(
    "Invalid JSON boundaries are rejected before domain logic runs",
    arguments: InvalidJSONRequest.examples
  )
  func rejectsInvalidJSONBoundaries(example: InvalidJSONRequest) async throws {
    let api = try makeAPI()
    var headers: [String: String] = [:]
    if let contentType = example.contentType {
      headers["content-type"] = contentType
    }

    let response = await api.handle(
      HTTPRequestData(
        method: "POST",
        path: "/v1/passkeys/registration/options",
        headers: headers,
        body: example.body,
        requestID: "test-request"
      )
    )

    #expect(response.status == 400)
    #expect(try errorCode(response) == "invalid_request")
  }

  @Test func rejectsOversizedBodiesBeforeDecoding() async throws {
    let api = try makeAPI()
    let response = await api.handle(
      request(
        method: "POST",
        path: "/v1/passkeys/registration/options",
        body: Data(repeating: 0x41, count: PasskeyAPI.maximumBodyBytes + 1)
      )
    )

    #expect(response.status == 413)
    #expect(try errorCode(response) == "body_too_large")
  }

  @Test func protectedRouteUsesHashedBearerSession() async throws {
    let repository = InMemoryPasskeyRepository()
    let sessions = try SessionManager(store: InMemorySessionStore())
    let api = try makeAPI(repository: repository, sessions: sessions)
    let user = makeUser()
    try await repository.create(user: user, credential: try makeCredential(user: user))
    let session = try await sessions.issue(userID: user.id)

    let response = await api.handle(
      request(
        method: "GET",
        path: "/v1/me",
        headers: ["authorization": "Bearer \(session.token)"]
      )
    )
    let summary = try JSONDecoder().decode(UserSummaryResponse.self, from: response.body)

    #expect(response.status == 200)
    #expect(summary.username == user.username)
  }

  @Test func logoutRevokesThePresentedSession() async throws {
    let repository = InMemoryPasskeyRepository()
    let sessions = try SessionManager(store: InMemorySessionStore())
    let api = try makeAPI(repository: repository, sessions: sessions)
    let user = makeUser()
    try await repository.create(user: user, credential: try makeCredential(user: user))
    let session = try await sessions.issue(userID: user.id)
    let authorization = ["authorization": "Bearer \(session.token)"]

    let logout = await api.handle(
      request(method: "POST", path: "/v1/session/logout", headers: authorization)
    )
    let afterLogout = await api.handle(
      request(method: "GET", path: "/v1/me", headers: authorization)
    )

    #expect(logout.status == 204)
    #expect(logout.body.isEmpty)
    #expect(afterLogout.status == 401)
  }

  @Test func hidesAuthenticationAndUnknownRouteDetails() async throws {
    let api = try makeAPI()

    let unauthorized = await api.handle(request(method: "GET", path: "/v1/me"))
    let unknown = await api.handle(request(method: "GET", path: "/debug/secrets"))

    #expect(unauthorized.status == 401)
    #expect(try errorCode(unauthorized) == "unauthorized")
    #expect(unknown.status == 404)
    #expect(try errorCode(unknown) == "not_found")
  }

  @Test func listsOwnedCredentialsAndRevokesAllSessionsAfterRemoval() async throws {
    let repository = InMemoryPasskeyRepository()
    let sessions = try SessionManager(store: InMemorySessionStore())
    let api = try makeAPI(repository: repository, sessions: sessions)
    let user = makeUser()
    let first = try makeCredential(user: user, idByte: 0x22)
    let second = try makeCredential(user: user, idByte: 0x33)
    try await repository.create(user: user, credential: first)
    try await repository.add(credential: second, to: user.id)
    let session = try await sessions.issue(userID: user.id)
    let headers = ["authorization": "Bearer \(session.token)"]

    let list = await api.handle(request(method: "GET", path: "/v1/passkeys", headers: headers))
    let response = try JSONDecoder().decode(CredentialListResponse.self, from: list.body)
    #expect(
      response.credentials.map(\.id) == [Base64URL.encode(first.id), Base64URL.encode(second.id)])

    let removal = await api.handle(
      request(
        method: "DELETE",
        path: "/v1/passkeys/\(Base64URL.encode(first.id))",
        headers: headers
      )
    )
    let afterRemoval = await api.handle(request(method: "GET", path: "/v1/me", headers: headers))
    #expect(removal.status == 204)
    #expect(afterRemoval.status == 401)
  }

  @Test func refusesToRemoveTheLastCredential() async throws {
    let repository = InMemoryPasskeyRepository()
    let sessions = try SessionManager(store: InMemorySessionStore())
    let api = try makeAPI(repository: repository, sessions: sessions)
    let user = makeUser()
    let credential = try makeCredential(user: user)
    try await repository.create(user: user, credential: credential)
    let session = try await sessions.issue(userID: user.id)

    let response = await api.handle(
      request(
        method: "DELETE",
        path: "/v1/passkeys/\(Base64URL.encode(credential.id))",
        headers: ["authorization": "Bearer \(session.token)"]
      )
    )

    #expect(response.status == 409)
    #expect(try errorCode(response) == "last_credential")
  }

  private func makeAPI(
    repository: InMemoryPasskeyRepository = InMemoryPasskeyRepository(),
    sessions: SessionManager? = nil
  ) throws -> PasskeyAPI {
    let configuration = try RelyingPartyConfiguration(
      id: "passkeys.example.com",
      name: "Passkey Lab",
      allowedOrigins: ["https://passkeys.example.com"]
    )
    return PasskeyAPI(
      passkeys: PasskeyService(
        configuration: configuration,
        repository: repository,
        ceremonies: InMemoryCeremonyStore()
      ),
      sessions: try sessions ?? SessionManager(store: InMemorySessionStore()),
      appleApplicationID: "TEAMID.com.example.PasskeyLab"
    )
  }

  private func request(
    method: String,
    path: String,
    headers: [String: String] = [:],
    body: Data = Data()
  ) -> HTTPRequestData {
    var headers = headers
    if !body.isEmpty, headers["content-type"] == nil {
      headers["content-type"] = "application/json"
    }
    return HTTPRequestData(
      method: method,
      path: path,
      headers: headers,
      body: body,
      requestID: "test-request"
    )
  }

  private func errorCode(_ response: HTTPResponseData) throws -> String {
    let object = try #require(
      JSONSerialization.jsonObject(with: response.body) as? [String: Any]
    )
    return try #require(object["code"] as? String)
  }

  private func makeUser() -> UserAccount {
    UserAccount(
      id: UUID(uuidString: "F59B80E5-3498-4DB5-A9CD-441963AB3B71")!,
      userHandle: Data(repeating: 0x11, count: 32),
      username: "alice@example.com",
      displayName: "Alice",
      createdAt: Date(timeIntervalSince1970: 1_800_000_000)
    )
  }

  private func makeCredential(user: UserAccount, idByte: UInt8 = 0x22) throws -> CredentialRecord {
    CredentialRecord(
      id: Data(repeating: idByte, count: 32),
      userID: user.id,
      userHandle: user.userHandle,
      publicKey: try COSEEC2PublicKey(
        algorithm: -7,
        curve: 1,
        x: Data(repeating: 0x33, count: 32),
        y: Data(repeating: 0x44, count: 32)
      ),
      rawPublicKey: Data(),
      aaguid: Data(repeating: 0, count: 16),
      signCount: 0,
      backupEligible: false,
      backupState: false,
      createdAt: user.createdAt
    )
  }
}

private struct Health: Codable {
  let status: String
}

/// Named input makes the violated HTTP precondition visible in test output.
struct InvalidJSONRequest: CustomTestStringConvertible, Sendable {
  let name: String
  let contentType: String?
  let body: Data

  var testDescription: String { name }

  static let examples = [
    InvalidJSONRequest(
      name: "missing content type",
      contentType: nil,
      body: Data("{}".utf8)
    ),
    InvalidJSONRequest(
      name: "non-JSON content type",
      contentType: "text/plain",
      body: Data("{}".utf8)
    ),
    InvalidJSONRequest(
      name: "empty JSON body",
      contentType: "application/json",
      body: Data()
    ),
    InvalidJSONRequest(
      name: "malformed JSON body",
      contentType: "application/json",
      body: Data("{".utf8)
    ),
  ]
}
