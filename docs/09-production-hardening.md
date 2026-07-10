# Production Hardening Checklist

The lab is not production-ready merely because the WebAuthn verifier is strict. Production authentication is a distributed system, a lifecycle, and a recovery policy. Use this chapter as a design gate.

## 1. Persistent account and credential model

Minimum credential fields:

- opaque credential ID with a global uniqueness constraint;
- account foreign key;
- stable user handle;
- COSE algorithm and public key bytes;
- AAGUID if retained under privacy policy;
- signature counter;
- BE and current BS;
- created, last-used, and revoked timestamps;
- user-visible credential label and optional transport hints;
- version column for optimistic concurrency.

Requirements:

- account plus first credential commit atomically;
- username canonicalization and uniqueness are product-defined and database-enforced;
- credential ID lookup is indexed and does not depend on user-supplied username;
- counter/backup update is transactional;
- schema migrations are forward/backward compatible during rollout;
- backup and restore preserve credential/public-key integrity.

## 2. Distributed ceremony store

Required properties:

- cryptographically random challenges of at least 16 bytes; the lab uses 32;
- random, non-enumerable ceremony IDs;
- purpose and expected account context stored server-side;
- fixed TTL and capacity limits;
- atomic consume exactly once across every instance;
- no retry after a failed completion;
- safe cleanup and metrics for issued, consumed, expired, and rejected ceremonies;
- redaction: challenges and credential responses do not belong in routine logs.

An eventually consistent cache without atomic read-delete is insufficient.

## 3. TLS and trusted proxies

- expose every ceremony endpoint only through HTTPS;
- use certificates valid for every allowed origin/AASA host;
- terminate TLS at a controlled proxy or in-process endpoint;
- define the exact proxy hops whose forwarding headers are trusted;
- do not derive RP ID or allowed origin from an arbitrary `Host`, `Origin`, or forwarding header;
- set header/body/read/idle deadlines;
- bound headers, URI length, body size, and concurrent requests;
- use graceful shutdown so in-flight completions finish predictably;
- keep AASA available without auth or redirect.

The lab's SwiftNIO listener is intentionally plain HTTP for local/proxy use.

## 4. Rate limiting and abuse controls

Apply independent controls to:

- registration options by IP/device/account identifier;
- authentication options without creating a username-existence oracle;
- completion attempts by ceremony ID and network context;
- session-protected endpoints;
- credential add/remove and recovery;
- help-desk and notification workflows.

Distributed limits need a shared, failure-aware store. Define fail-open vs fail-closed behavior per endpoint. A rate-limit outage should not accidentally disable challenge single-use.

## 5. Session policy

Decide explicitly:

- cookie vs bearer by client type;
- absolute and idle TTL;
- refresh-token design and rotation;
- session scope and recent-authentication timestamp;
- device/session list shown to the user;
- one-session and all-session revocation;
- revocation after credential deletion, recovery, password reset, or risk event;
- secure client storage;
- CSRF protection for browser cookies;
- token hashing/encryption and key rotation;
- response caching and referrer/log leakage controls.

The lab uses a non-sliding eight-hour bearer and hashes it in storage. That is a teaching default, not a universal policy.

## 6. Credential lifecycle

Users need:

- multiple Passkeys per account;
- useful labels and last-used timestamps;
- safe credential removal;
- recent WebAuthn step-up before adding a new credential;
- notification when a credential is added or removed;
- prevention of deleting the last recovery path without a replacement decision;
- all-session revocation during incident response;
- account deletion that removes RP public state and relevant sessions.

Do not use the first-account registration endpoint to add a credential to an existing account.

## 7. Recovery defines effective security

Model at least:

- lost all devices;
- compromised email account;
- SIM swap;
- stolen active session;
- malicious or socially engineered help-desk request;
- family/shared account and deceased/incapacitated user cases;
- enterprise administrator recovery.

Possible mechanisms include another Passkey, a verified existing session/device, offline recovery codes, delayed recovery with multi-channel notification, or high-assurance identity proofing. Every easier recovery path can become the attacker's preferred authentication path.

Recovery should trigger risk review, notifications, credential/session inventory review, and often a cooling-off period for sensitive actions.

## 8. Attestation policy

Keep `attestation: none` unless the product needs authenticator provenance, such as managed workforce hardware requirements.

If enabling attestation:

- document the exact accepted formats and algorithms;
- validate format-specific signatures and certificate requirements;
- establish trust roots and revocation/update processes;
- decide how FIDO Metadata Service data is obtained, cached, and failed;
- minimize retained AAGUID/certificate data;
- evaluate user privacy and device fingerprinting;
- create fixtures for every accepted/rejected trust path.

Never request attestation and then treat unverified attestation fields as trustworthy.

## 9. Observability and audit

Useful structured events:

- registration issued/succeeded/rejected;
- authentication issued/succeeded/rejected;
- coarse rejection category, not raw secret/input;
- credential added/renamed/revoked;
- session issued/revoked/expired;
- recovery started/completed/canceled;
- configuration/version/algorithm policy deployed.

Include request ID, server version, RP ID policy version, credential/account pseudonymous IDs where appropriate, and latency. Do not log challenges, session tokens, full client data, signatures, public-key coordinates by default, biometric information, or user-visible secrets.

Alert on anomaly rates, counter rollback, credential-add bursts, recovery plus sensitive action, unexpected origins/RP hashes, and verification-parser error spikes.

## 10. Privacy and retention

- keep user handles opaque and RP-local;
- collect no biometric data;
- justify AAGUID/attestation retention;
- define retention for IP/device/audit data;
- provide account and credential deletion behavior;
- protect backups and lower environments;
- avoid copying production credential/session data into test fixtures;
- document synced-Passkey implications without claiming knowledge of the user's biometric method.

## 11. Delivery and dependency security

- pin and review SwiftNIO/Swift Crypto updates;
- run tests on the exact Swift toolchain and Linux deployment image;
- generate an SBOM and vulnerability process;
- minimize container/runtime privileges;
- use read-only filesystems where practical;
- sign artifacts and protect CI credentials;
- test migration, rollback, and backup restore;
- keep environment validation at startup and fail closed on invalid RP/origin policy.

## 12. Required production tests

- W3C/known-good test vectors for every accepted algorithm;
- parser fuzzing and resource-limit tests;
- multi-instance challenge-consumption race;
- credential-update concurrency;
- database uniqueness and transaction rollback;
- TLS/proxy header spoofing tests;
- rate-limit behavior under shared-store outage;
- session revocation propagation;
- AASA availability and no-redirect monitor;
- end-to-end real-device registration/authentication in a staging RP;
- recovery tabletop exercise and incident runbook test.

## Release gate

Do not call the system production-ready until every item is one of:

- implemented and verified;
- explicitly not applicable with rationale;
- recorded as a known risk with owner, mitigation, and deadline.

“The WebAuthn library/test passed” is not an answer for persistence, recovery, session theft, proxy trust, privacy, or incident response.
