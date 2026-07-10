# Threat Model

## Assets

- ability to authenticate as an account;
- credential public-key/account binding;
- authenticator-held private key;
- application session bearers;
- recovery mechanisms;
- account and audit privacy;
- availability of registration/authentication/recovery.

## Trust boundaries

| Boundary | Trust assumption |
| --- | --- |
| authenticator to client platform | platform reports signed authenticator output; RP still verifies it |
| app to RP over network | all request data is hostile until TLS endpoint and RP verification |
| proxy to RP | only explicitly configured proxies and headers are trusted |
| RP process to stores | storage operations may fail/race; uniqueness and atomicity are enforced |
| session bearer to API | possession authorizes only within scope/expiry; theft is possible |
| recovery operator/system | may be attacked through social engineering and compromised channels |

## In-scope attackers

- remote unauthenticated caller;
- phishing site controlling another origin;
- caller replaying or mutating captured responses;
- user trying to bind one credential to another account;
- attacker with a stolen session bearer;
- attacker with read-only credential/session database access;
- compromised reverse-proxy configuration or spoofed forwarding headers;
- concurrency attacker racing challenge use or counter updates;
- malicious recovery applicant/help-desk social engineer;
- resource-exhaustion input targeting CBOR/HTTP parsers.

## Key threats and controls

| Threat | Primary controls | Residual risk |
| --- | --- | --- |
| ceremony replay | random challenge, TTL, purpose binding, atomic consume | distributed store implementation must preserve atomicity |
| phishing origin | authenticator scope plus exact RP origin validation | compromised allowed origin/app remains powerful |
| wrong RP scope | signed RP ID hash comparison | RP/config/public-suffix mistakes |
| response tampering | ES256 signature over authenticator/client bytes | endpoint compromise before verification |
| credential substitution | top-level/embedded/stored ID comparison, user handle/account binding | repository authorization bugs |
| weak local verification | required UV option plus signed UV check | authenticator/platform assurance follows WebAuthn model |
| cloned authenticator | nonzero counter advancement and risk telemetry | synced Passkeys may use zero counter |
| parser exhaustion/ambiguity | strict Base64url, bounded deterministic CBOR, body limits | header/deadline/distributed capacity controls still required |
| credential DB theft | public keys only, no private key | usernames/metadata/privacy exposure |
| session DB theft | store token hashes, random 256-bit bearers | active bearer theft from client/transport/memory |
| recovery takeover | high-assurance recovery design, delay, notification, step-up | product-specific human/process risk |

## Explicit non-goals of the lab adapter

- resisting server host/root compromise;
- durable or distributed storage;
- production TLS implementation;
- DDoS protection;
- full attestation trust verification;
- complete recovery and credential-management UI;
- browser cookie/CSRF design;
- malware-resistant storage of the native app session token.

These are production design requirements, not limitations of the WebAuthn protocol itself.

## Abuse cases to review

1. An attacker obtains a registration ceremony ID and submits invalid data repeatedly.
2. A proxy retries a completion request after the upstream timed out.
3. Two server instances consume the same challenge concurrently.
4. A user with an active session adds an attacker's Passkey without recent step-up.
5. A recovery flow bypasses every Passkey control through compromised email.
6. A stolen bearer remains usable after credential removal.
7. A deployment accepts `X-Forwarded-Host` from the public internet and derives origin policy from it.
8. A huge CBOR length or HTTP stream consumes memory before validation.
9. Error messages reveal whether a username or credential exists.
10. Audit logs accidentally store session tokens or complete credential responses.

For each production design review, assign an owner, prevention, detection, response, and test to every applicable abuse case.
