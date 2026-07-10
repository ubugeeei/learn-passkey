# Hands-on 3: Authentication, Signature Verification, and Sessions

## Goal

Verify possession of a registered private key, bind the assertion to the right account and RP context, update credential metadata safely, and issue a separate application session.

Relevant code:

- `Sources/PasskeyServer/AuthenticationVerifier.swift`
- `Sources/PasskeyServer/PasskeyService+Completion.swift`
- `Sources/PasskeyServer/Sessions.swift`
- `Sources/PasskeyHTTP/PasskeyAPI.swift`

## 1. Username-less and username-hinted options

Passkeys are discoverable credentials. `beginAuthentication()` can return an empty `allowCredentials` list and let the platform show accounts for the RP ID. The returned `userID`/user handle identifies the account after the user chooses a credential.

When a username hint is supplied and found, the server returns that account's credential IDs in `allowCredentials`. If the username is unknown, it returns an empty list instead of an explicit “account not found” error. A complete production anti-enumeration design also equalizes timing, rate limits, UI copy, and downstream behavior.

Each option response has a new challenge and ceremony state:

```text
authentication(expectedUserID?, requireUserHandle)
```

The username-less path requires a user handle. A username-constrained flow may accept a missing handle because the allowed credential and expected account already provide context, but any provided handle must still match.

## 2. Reconstruct the signed bytes

The assertion signature is over:

```text
authenticatorData || SHA-256(clientDataJSON)
```

Use the exact Base64url-decoded inputs. Do not serialize the parsed client-data object. JSON member order and insignificant formatting can change bytes while preserving meaning.

Swift Crypto's P-256 verifier applies SHA-256 as part of ES256 verification. The course:

1. converts the stored COSE x/y coordinates into X9.63 form;
2. parses the WebAuthn ECDSA signature as ASN.1 DER;
3. calls `isValidSignature(signature, for: signedData)`.

Malformed DER and an invalid mathematical signature are different internal failures but both become a coarse unauthorized response at the HTTP boundary.

## 3. Verification order

`AuthenticationVerifier.verify` checks:

1. response credential ID equals the selected stored record;
2. client-data type is `webauthn.get`;
3. challenge equals the consumed server challenge;
4. origin exactly matches policy;
5. authenticator data is structurally valid;
6. RP ID hash matches `SHA-256(configured RP ID)`;
7. UP is set;
8. UV is set when required;
9. registration-only AT data is absent;
10. BE has not changed since registration;
11. required/provided user handle equals the stored opaque handle;
12. the ES256 signature is valid;
13. a supported nonzero signature counter advances.

Only after all checks pass does the repository update `signCount`, backup state, and `lastUsedAt`.

## 4. Counter policy

The lab policy is:

```text
stored = 0, received = 0  -> supported behavior for counters that remain zero
stored = 0, received > 0  -> accept and start tracking
stored > 0, received > stored -> accept and update
otherwise -> reject as non-advancing counter
```

W3C treats a non-advancing nonzero counter as a signal that may indicate a cloned authenticator. A production risk engine may choose step-up or account protection instead of immediate rejection. Record that policy explicitly; do not silently ignore the signal.

BE is immutable for a credential. BS may change as backup state changes. The code rejects BE changes and records the current BS only after signature verification.

## 5. Application session design

After the assertion succeeds, `SessionManager` generates 32 random bytes and returns unpadded Base64url to the client. The store receives only:

```text
SHA-256(raw session token)
```

The session has an eight-hour default TTL in the lab. Authentication does not slide that expiry. Logout deletes the hash. `revokeAll(userID:)` supports incident response and credential lifecycle operations.

This design still requires TLS and careful client storage. A bearer stolen from app memory or transport can be used until expiry/revocation. Hashing primarily reduces the impact of a read-only session-database leak.

For a browser client, prefer a Secure, HttpOnly, SameSite cookie and a deliberate CSRF model. The native lab uses an Authorization bearer so the distinction is visible.

## 6. Run and inspect

```sh
swift test --filter CeremonyVerificationTests
swift test --filter SessionTests
swift test --filter PasskeyAPITests
```

Find these test cases:

- signature created by another private key;
- valid signature with a repeated counter;
- session expiry and removal;
- logout followed by protected-route failure;
- hidden authentication error details.

## Exercises

1. Flip one bit of `clientDataJSON` after signing. Identify whether client-data policy or signature verification fails first.
2. Sign an assertion with the correct key but a wrong RP ID hash. Explain why a valid signature alone is insufficient.
3. Remove the user-handle check and write a cross-account credential substitution test.
4. Change a credential from BE=false to BE=true in a signed assertion fixture. Confirm rejection.
5. Add session scopes or an `authenticatedAt` timestamp for a hypothetical money-transfer step-up policy.

## Completion criteria

- You can build the assertion signed bytes by hand.
- Wrong credential, challenge, type, origin, RP ID, flags, handle, key, or counter fails closed.
- Credential state changes only after verification.
- You can explain what a session-token hash protects and what it does not.
- You can explain why Passkey verification and ordinary API authorization are separate layers.
