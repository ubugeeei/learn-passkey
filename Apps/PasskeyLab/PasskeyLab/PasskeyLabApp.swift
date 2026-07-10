import AuthenticationServices
import PasskeyClient
import SwiftUI
import UIKit

@main
struct PasskeyLabApp: App {
  @State private var model: PasskeyViewModel

  @MainActor
  init() {
    let api = try! PasskeyAPIClient(baseURL: AppConfiguration.apiBaseURL)
    let authorization = PasskeyAuthorizationService {
      let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
      return
        scenes
        .flatMap(\.windows)
        .first(where: \.isKeyWindow) ?? UIWindow()
    }
    _model = State(
      initialValue: PasskeyViewModel(
        api: api,
        authorization: authorization
      )
    )
  }

  var body: some Scene {
    WindowGroup {
      ContentView(model: model)
    }
  }
}
