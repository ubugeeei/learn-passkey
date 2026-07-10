# Course Roadmap

## How this course works

A Passkey is not one API call. It is a protocol and product system spanning an authenticator, client platform, application, relying-party server, web origin, account model, and recovery policy. The course therefore builds from observable bytes and trust boundaries rather than beginning with a polished login screen.

Every phase uses five completion lenses:

- **Explain** — state why a value or check exists in your own words.
- **Inspect** — locate that value in real bytes or server state.
- **Implement** — implement the behavior without delegating the important check to a WebAuthn library.
- **Attack** — demonstrate what fails when the check is removed or changed.
- **Operate** — decide how the behavior works across expiry, revocation, failure, and multiple service instances.

## Phase 0 — Foundations

### Step 0: Authentication mental model

Learn public/private keys, signatures, challenge-response, phishing resistance, RP ID, origin, authenticator, and application session.

Artifacts:

- entity and trust-boundary map;
- registration and authentication sequences;
- glossary of identifiers and flags.

### Step 1: Reproducible Swift environment

Use Nix for surrounding tools and the selected Apple toolchain for Swift and Apple SDKs.

```sh
nix develop
swift --version
just test
```

## Phase 1 — Understand the wire format

### Step 2: Base64url and protocol models

Implement strict unpadded Base64url. Treat challenges, credential IDs, user handles, public-key coordinates, signatures, and session tokens as opaque bytes rather than ordinary strings.

### Step 3: Bounded deterministic CBOR

Implement the WebAuthn/COSE subset of CBOR with definite lengths, shortest integer encodings, canonical map ordering, duplicate-key rejection, depth limits, and allocation limits.

### Step 4: Authenticator data and COSE keys

Parse:

```text
rpIdHash | flags | signCount | attestedCredentialData | extensions
```

Extract an ES256/P-256 public key and understand every flag before applying RP policy.

## Phase 2 — Build the relying-party server

### Step 5: Registration options

Generate an opaque 32-byte user handle and 32-byte challenge with a CSPRNG. Store the challenge with purpose and expiry. Keep the account pending until verification succeeds.

### Step 6: Registration verification

Verify ceremony type, challenge, origin, RP ID hash, UP, UV, attested credential data, credential ID, attestation format, algorithm, curve, coordinate length, and backup flags.

The lab policy is intentionally narrow:

- discoverable credential required;
- user verification required;
- ES256/P-256 only;
- `attestation: none` for privacy and a small trust surface.

### Step 7: Authentication verification

Reconstruct and verify:

```text
authenticatorData || SHA-256(clientDataJSON)
```

Then enforce credential ID, user handle, RP ID, origin, UP/UV, backup eligibility, and signature-counter policy.

### Step 8: Sessions and HTTP

Separate the Passkey ceremony from application authentication state. Issue a 256-bit bearer, store only its SHA-256 hash, apply expiry and revocation, and expose the domain through a bounded SwiftNIO adapter.

## Phase 3 — Build the Apple client

### Step 9: iOS registration

Use `ASAuthorizationPlatformPublicKeyCredentialProvider` to create a registration request. Forward `credentialID`, `rawClientDataJSON`, and `rawAttestationObject` exactly as returned.

### Step 10: iOS authentication

Create modal and AutoFill-assisted assertion requests. Forward `rawAuthenticatorData`, `signature`, `userID`, and the untouched client-data JSON.

### Step 11: Associated Domains

Configure both sides of the association:

- app entitlement: `webcredentials:<rp-domain>`;
- server: `/.well-known/apple-app-site-association` with the signed application ID.

Test on a real device with HTTPS, signing, Developer Mode, and the appropriate development alternate mode.

## Phase 4 — Make the design operationally honest

### Step 12: Attack-oriented tests

Exercise challenge replay, expiry, wrong type, wrong origin, wrong RP ID, missing UV, credential substitution, altered backup flags, invalid signatures, counter replay, malformed CBOR, oversized HTTP bodies, and session revocation.

### Step 13: Credential lifecycle

Design multiple credentials per account, credential labels, last-used metadata, deletion, step-up before adding a credential, all-session revocation, and account deletion.

### Step 14: Recovery

Recovery defines the effective strength of the authentication system. Evaluate verified devices, recovery codes, identity proofing, help-desk procedures, delays, notifications, and attacker-visible account enumeration.

### Step 15: Production review

Evaluate whether the SQLite adapter fits the topology, replace it with a shared store where required, and review transactions, distributed challenge use, proxy trust, rate limits, logging, privacy, monitoring, backup/restore, and incident response.

## Suggested pace

| Phase | Time | Hands-on ratio |
| --- | ---: | ---: |
| Foundations | 2–3 hours | 40% |
| Wire format | 6–10 hours | 80% |
| RP server | 10–16 hours | 85% |
| Apple client | 6–10 hours | 80% |
| Operations | 8–16 hours | 70% |

Do not optimize for finishing quickly. Optimize for answering: “Where did this byte come from, who controls it, what is it bound to, and why may the RP trust it now?”

## Final project

Build a small service under an RP ID and Bundle ID you control. Completion means:

- a real iPhone registers and authenticates with a Passkey;
- the account can hold at least two credentials and revoke one safely;
- replay, wrong origin, wrong RP ID, and invalid signature tests fail closed;
- credentials survive a server restart and challenge consumption remains atomic across instances;
- the recovery policy and threat model are written down;
- every unmet production checklist item is recorded as an explicit limitation.
