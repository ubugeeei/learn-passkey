import Foundation
import PasskeyCore
import Testing

@testable import PasskeyClient

@Suite struct PasskeyAPIClientTests {
  @Test(arguments: [
    "http://passkeys.example.com",
    "https://passkeys.example.com/api",
    "https://user@passkeys.example.com",
    "https://passkeys.example.com?debug=true",
  ])
  func rejectsBaseURLsThatAreNotExactHTTPSOrigins(value: String) throws {
    let url = try #require(URL(string: value))

    #expect(throws: PasskeyAPIClientError.invalidBaseURL) {
      try PasskeyAPIClient(baseURL: url, transport: unusedTransport)
    }
  }

  @Test func registrationOptionsUseTypedPOSTRequest() async throws {
    let expected = RegistrationOptionsResponse(
      ceremonyID: "ceremony",
      publicKey: PublicKeyCredentialCreationOptions(
        rp: .init(id: "passkeys.example.com", name: "Passkey Lab"),
        user: .init(id: "AQ", name: "alice@example.com", displayName: "Alice"),
        challenge: "Ag",
        pubKeyCredParams: [.init(alg: -7)],
        timeout: 300_000,
        excludeCredentials: [],
        authenticatorSelection: .init(residentKey: .required, userVerification: .required),
        attestation: .none
      )
    )
    let client = try makeClient { request in
      #expect(request.httpMethod == "POST")
      #expect(request.url?.path == "/v1/passkeys/registration/options")
      #expect(request.value(forHTTPHeaderField: "content-type") == "application/json")
      let body = try #require(request.httpBody)
      let decoded = try JSONDecoder().decode(BeginRegistrationRequest.self, from: body)
      #expect(decoded.username == "alice@example.com")
      return try response(status: 200, body: JSONEncoder().encode(expected))
    }

    let actual = try await client.beginRegistration(
      username: "alice@example.com",
      displayName: "Alice"
    )

    #expect(actual == expected)
  }

  @Test func exposesSafeServerErrorEnvelope() async throws {
    let body = Data(
      #"{"code":"invalid_ceremony","message":"Expired","requestID":"req-1"}"#.utf8
    )
    let client = try makeClient { _ in
      try response(status: 400, body: body)
    }

    await #expect(
      throws: PasskeyAPIClientError.server(
        status: 400,
        code: "invalid_ceremony",
        message: "Expired",
        requestID: "req-1"
      )
    ) {
      try await client.beginAuthentication()
    }
  }

  @Test func sendsBearerOnlyToProtectedEndpoint() async throws {
    let user = UserSummaryResponse(id: UUID().uuidString, username: "alice", displayName: "Alice")
    let client = try makeClient { request in
      #expect(request.url?.path == "/v1/me")
      #expect(request.value(forHTTPHeaderField: "authorization") == "Bearer opaque-token")
      #expect(request.httpBody == nil)
      return try response(status: 200, body: JSONEncoder().encode(user))
    }

    #expect(try await client.currentUser(sessionToken: "opaque-token") == user)
  }

  @Test func rejectsMalformedSuccessResponse() async throws {
    let client = try makeClient { _ in
      try response(status: 200, body: Data("not-json".utf8))
    }

    await #expect(throws: PasskeyAPIClientError.invalidResponseBody) {
      try await client.beginAuthentication()
    }
  }

  @Test func logoutAcceptsEmpty204AndSendsBearer() async throws {
    let client = try makeClient { request in
      #expect(request.url?.path == "/v1/session/logout")
      #expect(request.httpMethod == "POST")
      #expect(request.value(forHTTPHeaderField: "authorization") == "Bearer session")
      return try response(status: 204, body: Data())
    }

    try await client.logout(sessionToken: "session")
  }

  private func makeClient(
    transport: @escaping PasskeyAPIClient.Transport
  ) throws -> PasskeyAPIClient {
    try PasskeyAPIClient(
      baseURL: URL(string: "https://passkeys.example.com")!,
      transport: transport
    )
  }

  private func response(status: Int, body: Data) throws -> (Data, HTTPURLResponse) {
    let response = try #require(
      HTTPURLResponse(
        url: URL(string: "https://passkeys.example.com")!,
        statusCode: status,
        httpVersion: "HTTP/1.1",
        headerFields: ["content-type": "application/json"]
      )
    )
    return (body, response)
  }
}

private let unusedTransport: PasskeyAPIClient.Transport = { _ in
  throw PasskeyAPIClientError.nonHTTPResponse
}
