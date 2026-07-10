# Hands-on 4: The iOS Passkey Client

## Goal

Drive Apple's platform authenticator, preserve the exact WebAuthn response, and understand the two-way domain association required before a real device will allow the ceremony.

Relevant code:

- `Sources/PasskeyClient/PasskeyAPIClient.swift`
- `Sources/PasskeyClient/PasskeyAuthorizationService.swift`
- `Apps/PasskeyLab/PasskeyLab/PasskeyViewModel.swift`
- `Apps/PasskeyLab/PasskeyLab/PasskeyLab.entitlements`

## 1. Keep networking and OS authorization separate

`PasskeyAPIClient` moves typed JSON between the app and RP. `PasskeyAuthorizationService` drives AuthenticationServices. The view model composes them:

```text
RP options -> API client -> view model -> AuthenticationServices
raw credential <- API client <- view model <- AuthenticationServices
```

This separation makes it difficult to accidentally let HTTP code synthesize authenticator results or let UI code decide whether a signature is valid.

The API client accepts only an exact HTTPS origin as its base URL. It rejects a path, query, fragment, user info, and `http://`. A production client may use a custom transport for metrics or pinning experiments; tests inject a closure without changing protocol code.

## 2. Registration request

The app decodes the server's challenge and user handle from Base64url, then creates:

```swift
let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
    relyingPartyIdentifier: options.publicKey.rp.id
)
let request = provider.createCredentialRegistrationRequest(
    challenge: challenge,
    name: options.publicKey.user.name,
    userID: userID
)
```

It also applies display name, UV preference, and `attestationPreference = .none` from the server policy. AuthenticationServices presents system-owned UI and creates the credential.

On success, the app forwards:

- `credentialID`;
- `rawClientDataJSON`;
- `rawAttestationObject`.

The app does not parse the attestation object, does not generate a public/private key pair, and does not declare registration successful. The RP does that after verification and persistence.

## 3. Assertion request

The app creates an assertion request with RP ID and challenge. If the server supplied credential descriptors, it maps them to `ASAuthorizationPlatformPublicKeyCredentialDescriptor` values. It sets the UV preference and chooses modal or AutoFill-assisted presentation.

On success it forwards:

- `credentialID`;
- `rawClientDataJSON`;
- `rawAuthenticatorData`;
- `signature`;
- `userID` as the WebAuthn user handle.

The private key remains in the authenticator. The biometric remains local. The signature is not a session token.

## 4. Async delegate bridge

AuthenticationServices reports completion through a main-actor delegate. `PasskeyAuthorizationService` stores exactly one checked continuation and rejects overlapping operations. It immediately converts an Apple credential object into Sendable transport models before resuming the caller.

Important lifecycle rules:

- retain the `ASAuthorizationController` while UI is active;
- resume every continuation exactly once;
- clear controller and pending state on success or failure;
- treat an unexpected credential class as an error;
- allow explicit cancellation;
- keep presentation-anchor lookup on the main actor.

## 5. AutoFill-assisted Passkeys

The username field uses `.textContentType(.username)`. On iOS, the service can call `performAutoFillAssistedRequests()` so the system presents Passkey suggestions through familiar AutoFill UI. The API is unavailable on macOS, where the adapter falls back to modal presentation.

AutoFill affects presentation, not server verification. It still starts from a fresh RP challenge and ends with the same assertion checks.

## 6. Associated Domains is a two-way assertion

The app entitlement contains:

```text
webcredentials:passkeys.example.com?mode=developer
```

The server must serve, without a redirect:

```text
https://passkeys.example.com/.well-known/apple-app-site-association
```

with content equivalent to:

```json
{
  "webcredentials": {
    "apps": ["TEAMID.com.example.PasskeyLab"]
  }
}
```

The application ID is the App Identifier Prefix/Team ID plus Bundle ID. It is not merely the Bundle ID.

The development alternate mode bypasses Apple's CDN for a directly reachable private/development domain when the signed app and device satisfy Apple's development requirements. Remove `?mode=developer` before App Store distribution.

## 7. Configure the app

Replace placeholders:

1. Bundle ID in `PasskeyLab.xcodeproj`;
2. domain in `PasskeyLab.entitlements`;
3. API origin in `AppConfiguration.swift`;
4. `PASSKEY_APP_ID` on the server;
5. signing team in Xcode.

Open:

```sh
open Apps/PasskeyLab/PasskeyLab.xcodeproj
```

Select a real device. Confirm the Associated Domains capability matches the entitlement. Enable Developer Mode and, for alternate mode, Associated Domains Development on the device.

## 8. Client tests

The API client tests do not fake AuthenticationServices UI. They test the deterministic code surrounding that OS boundary:

```sh
swift test --filter PasskeyAPIClientTests
```

They verify:

- exact HTTPS-origin base URLs;
- typed endpoint and JSON construction;
- safe server-error decoding;
- Authorization bearer placement;
- malformed success-response rejection.

The OS ceremony requires an integration test on simulator/device with the associated domain. Do not claim the client is integration-tested when only transport unit tests ran.

## Exercises

1. Set a breakpoint in the authorization delegate and inspect the available fields. Confirm no private key or biometric data exists.
2. Decode `rawClientDataJSON` only for observation, then compare the original bytes with re-encoded JSON. Explain why the server hashes the original.
3. Cancel the system sheet. Confirm no completion request is sent and a new ceremony is required.
4. Attempt to use a domain not in the entitlement. Record the AuthenticationServices error.
5. Trigger AutoFill-assisted and modal flows and compare only presentation, not RP verification.

## Completion criteria

- The app uses server-provided RP ID, challenge, and user handle.
- Raw credential fields reach the server byte-for-byte.
- The app does not possess or generate the Passkey private key.
- AASA and entitlement application IDs match the signed build.
- Transport unit tests pass and device integration status is reported separately.
