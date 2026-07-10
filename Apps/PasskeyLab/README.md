# PasskeyLab iOS app

The app is a deliberately thin UI over the `PasskeyClient` package product. It demonstrates two boundaries:

1. `PasskeyAPIClient` exchanges typed JSON with the RP server.
2. `PasskeyAuthorizationService` presents Apple-owned Passkey UI and returns raw WebAuthn response bytes.

Before building on a device, replace all three placeholders with values you control:

- `com.example.PasskeyLab` in the Xcode target's Bundle Identifier
- `webcredentials:passkeys.example.com?mode=developer` in `PasskeyLab.entitlements`
- `https://passkeys.example.com` in `AppConfiguration.swift`

Set `PASSKEY_APP_ID=<TEAM_ID>.<BUNDLE_ID>` on the server so its AASA response matches the signed app. Select a development team in Xcode, enable Developer Mode and Associated Domains Development on the device, then open `PasskeyLab.xcodeproj`.

The lab keeps the application session token only in memory. A production app needs an explicit Keychain storage, rotation, revocation, and device-compromise policy; never confuse that bearer token with the Passkey private key, which remains under AuthenticationServices.
