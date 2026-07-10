# Learn Passkeys by Implementing Them in Swift

This repository is a from-zero, implementation-first course on Passkeys and WebAuthn. The client and server are both written in Swift. You will inspect the protocol bytes, implement the relying-party checks, drive Apple's AuthenticationServices API, and finish with the operational decisions needed for a real service.

The course intentionally uses very few libraries:

- **SwiftNIO** only for HTTP transport.
- **Swift Crypto** for portable SHA-256 and P-256 operations.
- **Swift Testing** for the test harness when full Xcode is not installed.
- Base64url, CBOR/COSE parsing, authenticator-data parsing, ceremony state, verification order, credential storage ports, and session policy are implemented in this repository.

## What you will be able to do

After completing the course, you should be able to:

- explain the relationship between public-key cryptography, WebAuthn, and Passkeys;
- trace registration and authentication byte-for-byte;
- explain RP ID, origin, challenge, credential ID, user handle, UP, UV, BE, BS, and `signCount`;
- decode `clientDataJSON`, attestation objects, authenticator data, and COSE keys;
- verify an ES256 assertion without hiding the logic behind a WebAuthn library;
- integrate an iOS app using AuthenticationServices and Associated Domains;
- design single-use challenges, credential lifecycle, application sessions, recovery, rate limits, audit events, and production persistence;
- review a Passkey implementation against the W3C relying-party algorithms and a concrete threat model.

## Start here

1. Read the [course roadmap](docs/00-roadmap.md).
2. Build the [mental model](docs/01-mental-model.md).
3. Enter the [Nix development environment](docs/02-environment.md).
4. Follow the hands-on chapters in numeric order.
5. Use the [production hardening checklist](docs/09-production-hardening.md) before treating any derivative as production-ready.

```sh
nix develop
just test
just server
```

The server starts on `http://127.0.0.1:8080`. A native Passkey ceremony requires a real HTTPS RP domain and a matching Associated Domains configuration; the local HTTP listener is designed to sit behind that development TLS endpoint.

## Repository map

| Path | Responsibility |
| --- | --- |
| `Sources/PasskeyCore` | Shared API models, strict Base64url, bounded CBOR, COSE, client data, and authenticator data |
| `Sources/PasskeyServer` | Ceremony orchestration, verifiers, repository ports, in-memory adapters, and hashed sessions |
| `Sources/PasskeyHTTP` | Safe public error mapping and the bounded SwiftNIO HTTP adapter |
| `Sources/PasskeyClient` | Typed RP API client and the AuthenticationServices bridge |
| `Apps/PasskeyLab` | SwiftUI iOS application, entitlement, and local package integration |
| `Tests` | Unit, integration, attack, transport, and synthetic-authenticator tests |
| `docs` | The complete hands-on course, architecture, threat model, and reference material |

The current suite contains 45 tests across protocol primitives, ceremonies, sessions, HTTP boundaries, and the client transport. Run `just test` whenever a chapter asks you to change an invariant.

## Important scope boundary

The code is deliberately strong at the WebAuthn protocol boundary, but the included process-local storage is a teaching adapter. The executable prints that warning at startup. A production deployment must replace or add:

- transactional persistent storage and uniqueness constraints;
- atomic distributed challenge consumption;
- TLS termination, trusted-proxy policy, request deadlines, and distributed rate limits;
- production secret/session storage and incident revocation;
- account recovery and credential-management product flows;
- audit/event pipelines, privacy retention, backups, and disaster recovery;
- an explicit attestation trust policy if attestation other than `none` is requested.

The [production chapter](docs/09-production-hardening.md) defines acceptance criteria for each item. Omitting those items is a known limitation, not an implicit production claim.

## Primary references

- [W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/)
- [Apple: Supporting passkeys](https://developer.apple.com/documentation/authenticationservices/supporting-passkeys)
- [Apple: Supporting associated domains](https://developer.apple.com/documentation/xcode/supporting-associated-domains)
- [RFC 4648: Base-N Encodings](https://www.rfc-editor.org/rfc/rfc4648.html)
- [RFC 8949: CBOR](https://www.rfc-editor.org/rfc/rfc8949.html)
- [RFC 9052: COSE Structures](https://www.rfc-editor.org/rfc/rfc9052.html)
- [RFC 9053: COSE Algorithms](https://www.rfc-editor.org/rfc/rfc9053.html)

Specifications and platform APIs evolve. Prefer the primary source when it conflicts with an explanation in this course.
