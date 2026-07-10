# Hands-on 2: Registration on the RP Server

## Goal

Issue secure registration options, keep the account pending, verify the complete response in the correct trust order, and atomically store the account and public credential.

Relevant code:

- `Sources/PasskeyServer/PasskeyService.swift`
- `Sources/PasskeyServer/PasskeyService+Completion.swift`
- `Sources/PasskeyServer/RegistrationVerifier.swift`
- `Sources/PasskeyServer/Stores.swift`

Relevant tests:

- `Tests/PasskeyServerTests/CeremonyAndOptionsTests.swift`
- `Tests/PasskeyServerTests/CeremonyVerificationTests.swift`

## 1. Server-held expectations

The server creates:

- a 24-byte random ceremony ID;
- a 32-byte random challenge;
- a 32-byte random user handle;
- purpose: registration plus pending account;
- expiry: five minutes by default.

The client receives the ceremony ID and public creation options. The challenge stored in `CeremonyState` is the expectation. A challenge echoed by the completion request is untrusted input.

`InMemoryCeremonyStore.consume` removes the record before validation continues. A malformed or malicious attempt cannot retry the same challenge.

## 2. Why the account stays pending

A tempting flow is:

1. insert user;
2. ask for a Passkey;
3. attach the credential later.

If the sheet is canceled or verification fails, that creates an account with no valid authentication method. It also makes account takeover bugs likely if the same endpoint can attach a key to an existing username.

The course stores `PendingRegistration` only in ceremony state. After verification, `PasskeyRepository.create(user:credential:)` checks both username and credential uniqueness and commits both objects together.

## 3. Creation options

The default options are deliberately opinionated:

```json
{
  "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
  "authenticatorSelection": {
    "residentKey": "required",
    "userVerification": "required"
  },
  "attestation": "none"
}
```

- ES256 keeps the first implementation narrow.
- A discoverable credential enables username-less authentication.
- UV is required and verified again on the server.
- `none` avoids collecting identifying authenticator provenance and avoids an attestation PKI until a product requirement justifies it.

The W3C Level 3 accessibility guidance recommends ceremony timeouts in the 5–10 minute range. The lab uses five minutes.

## 4. Verification order

`RegistrationVerifier.verify` follows this reasoning sequence:

1. Credential ID has a bounded, nonzero length.
2. Decode `clientDataJSON` without changing raw bytes.
3. `type == "webauthn.create"`.
4. Decoded challenge equals the consumed server challenge.
5. Origin exactly matches the configured allowed origin set.
6. Cross-origin and top-origin contexts are not allowed by this RP policy.
7. Decode the attestation object under CBOR limits.
8. Format is `none` and the attestation statement is empty.
9. `rpIdHash == SHA-256(configured RP ID)`.
10. UP is set.
11. UV is set because issued policy required it.
12. Attested credential data exists.
13. Embedded credential ID equals the top-level credential ID.
14. COSE key is EC2/ES256/P-256 with 32-byte coordinates.
15. Return public credential material for atomic persistence.

Registration with `none` attestation does not include an additional attestation-signature trust path. The authenticator-created credential key becomes useful when the first assertion is verified later.

## 5. Origin and RP ID are different checks

For a configuration such as:

```text
RP ID:          example.com
Allowed origin: https://login.example.com
```

the authenticator signs `SHA-256(example.com)` in authenticator data. Client data reports `https://login.example.com`. The relationship is valid, but the strings are not equal and serve different layers.

`RelyingPartyConfiguration` rejects:

- an RP ID containing a scheme, port, uppercase characters, empty labels, or invalid characters;
- a non-HTTPS origin;
- an origin with path, query, fragment, or user info;
- an origin host outside the RP ID's domain scope.

Configuration validation is necessary but not a public-suffix-list implementation. Before production, validate that your chosen RP ID is registrable and not a public suffix.

## 6. Run the registration tests

```sh
swift test --filter CeremonyAndOptionsTests
swift test --filter CeremonyVerificationTests
```

The synthetic authenticator creates a real P-256 key pair, emits deterministic CBOR structures, and later signs assertions. This is more valuable than testing only mocked “verification succeeded” booleans.

## Exercises

1. Change the options to `userVerification: preferred` but keep server verification required. Observe which layer fails and explain the inconsistent policy.
2. Change the origin in the synthetic client data. Confirm the ceremony is consumed even though verification fails.
3. Remove the top-level vs embedded credential ID comparison. Write a failing substitution test before restoring it.
4. Attempt two registrations for the same username concurrently. Describe which uniqueness constraint a production database must enforce.
5. Design—but do not merge into this endpoint—an “add another Passkey” flow requiring a valid session and recent WebAuthn step-up.

## Completion criteria

- You can distinguish every server-held expectation from client-supplied input.
- Failed registration creates no account.
- A challenge cannot be reused after success or failure.
- Wrong origin, RP ID, UV, attestation shape, credential ID, and COSE key fail closed.
- You can explain why adding a credential to an existing account is a different authorization flow.
