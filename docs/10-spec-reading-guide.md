# Specification Reading Guide

The goal is not to memorize the W3C document. It is to navigate from a received byte to the normative relying-party operation that constrains it.

Primary document: [Web Authentication: An API for accessing Public Key Credentials — Level 3](https://www.w3.org/TR/webauthn-3/).

Level 3 is on the W3C Recommendation track and may evolve. Recheck section numbering and requirements when updating the course.

## Read in this order

1. **Introduction and use cases** — understand registration/authentication actors.
2. **Terminology** — RP, authenticator, client, credential source, user handle, origin.
3. **Web Authentication API** — inputs/outputs visible to a client platform.
4. **Authenticator data** — fixed header, flags, attested credential data, extensions.
5. **RP operations: registering a new credential** — server verification algorithm.
6. **RP operations: verifying an assertion** — authentication verification algorithm.
7. **Attestation formats** — read `none` first; do not implement all formats casually.
8. **Security considerations** — challenge quality, origin validation, credential loss, injection.
9. **Privacy considerations** — user handles, attestation, enumeration, correlatability.
10. **Test vectors** — convert normative concepts into executable fixtures.

## Code-to-spec map

| Code | Specification concept |
| --- | --- |
| `Base64URL` | unpadded Base64url dependency |
| `CollectedClientData` / validator | client-data fields and RP type/challenge/origin checks |
| `CBORDecoder` | CTAP2 deterministic CBOR expectation |
| `AuthenticatorData` | authenticator data structure and flags |
| `COSEEC2PublicKey` | credential public key and COSE algorithm/key labels |
| `RegistrationVerifier` | RP registration operation under `none` attestation policy |
| `AuthenticationVerifier` | RP assertion verification operation |
| `CeremonyStore` | cryptographic challenge freshness and replay defense |
| `RelyingPartyConfiguration` | expected RP ID and origin policy |
| `PasskeyAuthorizationService` | Apple client-platform API mapping |

## RFC dependencies

### RFC 4648 — Base64url

Focus on URL-safe alphabet and padding behavior. WebAuthn uses no trailing `=` and no whitespace.

### RFC 8949 — CBOR

Read the data model, major types, preferred/deterministic serialization, map-key concerns, and decoder security considerations. WebAuthn/CTAP impose a deterministic form beyond “some valid CBOR.”

### RFC 9052 — COSE structures

Read COSE_Key common parameters and the fact that keys are CBOR maps with integer labels.

### RFC 9053 — COSE algorithms

Locate EC2/P-256 and ES256 assignments. Keep key type, curve, and algorithm as independent validated fields.

## Apple mapping

Read [Supporting passkeys](https://developer.apple.com/documentation/authenticationservices/supporting-passkeys) for the native flow and [Supporting associated domains](https://developer.apple.com/documentation/xcode/supporting-associated-domains) for the two-way app/domain association.

Important mappings:

| Apple property | WebAuthn/RP field |
| --- | --- |
| `credentialID` | raw credential ID |
| `rawClientDataJSON` | untouched client-data bytes |
| `rawAttestationObject` | registration attestation object CBOR |
| `rawAuthenticatorData` | assertion authenticator data bytes |
| `signature` | assertion signature, DER for ES256 |
| `userID` | RP-created user handle stored with the credential |

Apple's API owns the authenticator/client-platform side. It does not remove the RP server's verification obligations.

## How to audit a verifier

For every normative RP step, write:

1. the trusted expected value;
2. the untrusted received value;
3. the comparison/cryptographic operation;
4. the failure behavior;
5. the state change allowed after success;
6. the test that mutates this value.

Example:

```text
Expected: challenge bytes from consumed CeremonyState
Received: Base64url-decoded CollectedClientData.challenge
Check: constant-time byte comparison
Failure: typed challenge mismatch; public invalid ceremony/registration
State: no account/credential/session write
Test: challenge replay/mismatch fixture
```

If any received value is compared only to another value from the same request, the check probably lacks a trust anchor.

## Versioning discipline

When the spec or SDK changes:

- record the reviewed W3C snapshot/date and Apple SDK version;
- compare normative algorithm changes, flags, extensions, and new algorithms;
- add a failing test before changing the parser/verifier;
- keep unknown/reserved values fail-closed unless the specification explicitly defines forward-compatible handling;
- update the source link and course explanation with the code change.
