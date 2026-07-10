import Foundation
import PasskeyHTTP
import PasskeyServer

@main
struct PasskeyServerMain {
  static func main() throws {
    let environment = ProcessInfo.processInfo.environment
    let rpID = environment["PASSKEY_RP_ID"] ?? "passkeys.example.com"
    let rpName = environment["PASSKEY_RP_NAME"] ?? "Passkey Lab"
    let allowedOrigins = Set(
      (environment["PASSKEY_ALLOWED_ORIGINS"] ?? "https://passkeys.example.com")
        .split(separator: ",")
        .map(String.init)
    )
    let appID = environment["PASSKEY_APP_ID"] ?? "TEAMID.com.example.PasskeyLab"
    let host = environment["PASSKEY_HOST"] ?? "127.0.0.1"
    let port = Int(environment["PASSKEY_PORT"] ?? "8080") ?? 8080

    let repository = InMemoryPasskeyRepository()
    let passkeys = PasskeyService(
      configuration: try RelyingPartyConfiguration(
        id: rpID,
        name: rpName,
        allowedOrigins: allowedOrigins
      ),
      repository: repository,
      ceremonies: InMemoryCeremonyStore()
    )
    let sessions = try SessionManager(store: InMemorySessionStore())
    let api = PasskeyAPI(
      passkeys: passkeys,
      sessions: sessions,
      appleApplicationID: appID
    )

    print("WARNING: in-memory stores are for the hands-on lab, not production persistence.")
    try PasskeyHTTPServer(api: api).run(host: host, port: port)
  }
}
