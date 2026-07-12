import PasskeyClient
import SwiftUI

struct ContentView: View {
  @Bindable var model: PasskeyViewModel

  var body: some View {
    NavigationStack {
      Form {
        Section("Account") {
          TextField("Username", text: $model.username)
            .textContentType(.username)
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
          TextField("Display name", text: $model.displayName)
        }

        Section("Passkey ceremonies") {
          Button("Create account with a Passkey") {
            Task { await model.register() }
          }
          Button("Sign in with a Passkey") {
            Task { await model.signIn() }
          }
          Button("Try AutoFill-assisted sign-in") {
            Task { await model.signIn(presentation: .autoFill) }
          }
        }
        .disabled(model.phase.isBusy)

        Section("Application session") {
          phaseView
          Button("Sign out", role: .destructive) {
            Task { await model.signOut() }
          }
        }

        if case .signedIn = model.phase {
          Section("Your Passkeys") {
            ForEach(model.credentials) { credential in
              VStack(alignment: .leading) {
                Text(String(credential.id.prefix(12)) + "…")
                  .font(.system(.body, design: .monospaced))
                Text(credential.lastUsedAt == nil ? "Not used yet" : "Previously used")
                  .font(.caption)
                  .foregroundStyle(.secondary)
              }
              .swipeActions {
                Button("Remove", role: .destructive) {
                  Task { await model.removeCredential(id: credential.id) }
                }
                .disabled(model.credentials.count == 1)
              }
            }
            Button("Add another Passkey") {
              Task { await model.addCredential() }
            }
          }
        }
      }
      .navigationTitle("Passkey Lab")
      .overlay {
        if model.phase.isBusy {
          ProgressView()
            .controlSize(.large)
        }
      }
    }
  }

  @ViewBuilder
  private var phaseView: some View {
    switch model.phase {
    case .signedOut:
      Text("Signed out")
        .foregroundStyle(.secondary)
    case .registering:
      Text("Creating credential…")
    case .authenticating:
      Text("Verifying assertion…")
    case .managingCredentials:
      Text("Updating Passkeys…")
    case .signedIn(let user):
      LabeledContent("Signed in", value: user.displayName)
    case .failed(let message):
      Text(message)
        .foregroundStyle(.red)
        .textSelection(.enabled)
    }
  }
}
