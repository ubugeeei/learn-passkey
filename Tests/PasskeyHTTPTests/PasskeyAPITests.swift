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

  @Test(arguments: [
    (nil, Data("{}".utf8)),
    ("text/plain", Data("{}".utf8)),
    ("application/json", Data()),
    ("application/json", Data("{".utf8)),
  ])
  func rejectsInvalidJSONBoundaries(contentType: String?, body: Data) async throws {
    let api = try makeAPI()
    var headers: [String: String] = [:]
    if let contentType {
      headers["content-type"] = contentType
    }

    let response = await api.handle(
      HTTPRequestData(
        method: "POST",
        path: "/v1/passkeys/registration/options",
        headers: headers,
        body: body,
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

  private func makeCredential(user: UserAccount) throws -> CredentialRecord {
    CredentialRecord(
      id: Data(repeating: 0x22, count: 32),
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
