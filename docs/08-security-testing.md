# Hands-on 6: Security and Attack-Oriented Testing

## Test philosophy

Success-path tests prove that one valid transcript works. Authentication confidence comes from showing that each altered binding fails for the right reason and that failure does not leave reusable state.

The current suite has 52 tests in 11 suites:

```sh
just test
```

## Test layers

| Layer | What it proves |
| --- | --- |
| primitive unit tests | canonical encodings, bounds, flags, structured parse failures |
| pure verifier tests | RP-held expectations and cryptographic policy |
| service integration tests | one-time state, atomic persistence, metadata updates |
| HTTP API tests | size/content boundaries, safe errors, auth headers, logout |
| client transport tests | exact HTTPS origin, typed JSON, bearer placement |
| device integration | entitlement/AASA/signing/OS authenticator behavior |

No one layer substitutes for the others.

## Existing mutation matrix

| Mutation | Expected rejection |
| --- | --- |
| padded/invalid Base64url | `Base64URLError` or coarse invalid request |
| non-shortest CBOR integer | `nonCanonicalInteger` |
| duplicate CBOR map key | `duplicateMapKey` |
| wrong canonical map order | `nonCanonicalMapOrder` |
| too much CBOR nesting/string data | resource-limit error |
| reserved authenticator flag | structural authenticator error |
| BS without BE | structural authenticator error |
| wrong ceremony challenge | challenge mismatch; ceremony remains consumed |
| wrong registration origin | unexpected origin |
| wrong RP ID hash | RP ID hash mismatch |
| missing registration UV | user verification required |
| assertion signed by another key | invalid signature |
| valid signature with repeated nonzero counter | counter did not advance |
| expired session | invalid session and removal |
| oversized HTTP body | 413 before JSON decoding |
| missing bearer | coarse 401 |
| logout followed by `/v1/me` | coarse 401 |

## Add a regression test correctly

1. Describe the invariant in one sentence.
2. Construct a valid transcript with `TestAuthenticator`.
3. Mutate one property only.
4. Assert the precise domain error.
5. Assert server state: challenge consumed, account absent, credential unchanged, or session revoked as applicable.
6. Confirm the HTTP layer maps the precise error to a coarse public response.
7. Restore the mutation and confirm the valid transcript still succeeds.

Avoid a fixture that builds arbitrary “already verified” objects; it bypasses the bytes you need to test.

## Recommended additional tests

Implement these as exercises:

### Parser cases

- truncated AAGUID and credential ID;
- credential ID length zero and over 1,024 bytes;
- 31/33-byte P-256 coordinates;
- unsupported `kty`, `alg`, and `crv`;
- ED set with absent/malformed extension CBOR;
- trailing bytes after assertion authenticator data;
- invalid UTF-8 CBOR text;
- very large declared string before allocation.

### Registration cases

- `type = webauthn.get` in a registration response;
- `fmt = none` with a nonempty statement;
- missing UP;
- top-level credential ID differs from embedded ID;
- duplicate credential ID across accounts;
- simultaneous same-username completion race.

### Authentication cases

- missing user handle in discoverable flow;
- handle from another account;
- AT unexpectedly present;
- BE changes after registration;
- valid signature over a wrong challenge;
- malformed but parseable DER edge cases;
- stored counter nonzero, received zero;
- two concurrent valid assertions with the same next counter.

### Service and HTTP cases

- ceremony purpose confusion;
- exact expiry-boundary behavior;
- malformed content length and chunked body beyond the streaming limit;
- multiple Authorization headers;
- query strings on security-sensitive routes;
- session token padding/length errors;
- all-session revocation;
- repository error maps to 500 without leaking details.

## Fuzzing and corpus testing

The strict parsers are good fuzz targets because they are pure and bounded. A production project should add:

- a corpus seeded from W3C test vectors;
- random byte inputs to Base64url/CBOR/authenticator parsers;
- mutation of length fields, flags, and CBOR heads;
- assertions for no crash, no unbounded allocation, deterministic result, and acceptable runtime;
- differential tests against a mature WebAuthn implementation, with differences reviewed rather than blindly copied.

Fuzzing is complementary to specification-derived tests. A fuzzer may find a crash but cannot tell you that an origin check is missing.

## Timing and concurrency

Logical single-use behavior must survive concurrency. In-memory actor serialization proves only one process. The SQLite adapter test races two connections and accepts exactly one consume. A production integration test must repeat this with the actual deployment store and multiple server instances.

Similarly, credential counter updates need an optimistic concurrency or transactional rule. Two valid assertions based on the same stored counter should not both commit silently if your policy treats that as risk.

## Completion criteria

- Every security invariant has at least one failure test.
- Mutation tests change one binding at a time.
- Tests assert state after rejection, not just the thrown error.
- Public errors do not reveal internal cryptographic detail.
- Device integration and server tests are reported separately.
- A plan exists for fuzzing and multi-instance race testing.
