# Hands-on 1: WebAuthn Bytes

## Goal

Parse every registration/authentication byte structure needed by the RP while preserving the exact signed representation and bounding all attacker-controlled allocations.

Relevant code:

- `Sources/PasskeyCore/Base64URL.swift`
- `Sources/PasskeyCore/ByteCursor.swift`
- `Sources/PasskeyCore/CBOR.swift`
- `Sources/PasskeyCore/COSEKey.swift`
- `Sources/PasskeyCore/AuthenticatorData.swift`

Relevant tests:

- `Tests/PasskeyCoreTests/Base64URLTests.swift`
- `Tests/PasskeyCoreTests/CBORTests.swift`
- `Tests/PasskeyCoreTests/AuthenticatorDataTests.swift`

## 1. Base64url is a transport encoding

JSON cannot carry arbitrary bytes directly. WebAuthn JSON representations use the URL-safe alphabet from RFC 4648 with no trailing `=` padding.

```text
ordinary Base64:  + / and optional = padding
Base64url:        - _ and no padding in WebAuthn
```

The decoder is strict:

- rejects `=` rather than accepting multiple textual forms;
- rejects whitespace and ordinary `+` or `/` characters;
- rejects impossible length modulo four;
- adds padding only internally for Foundation's decoder.

Why canonical text matters: if separate layers accept different spellings of the same bytes, caching, signatures, equality checks, logging, and policy can disagree.

Run:

```sh
swift test --filter Base64URLTests
```

Exercise: temporarily allow `=` in `Base64URL.decode`, run the tests, then restore strict behavior.

## 2. Bounds-checked byte reading

Authenticator data mixes fixed-width fields and length-prefixed sections. Direct array indexing makes truncated input easy to mishandle. `ByteCursor` provides:

- one-byte reads;
- big-endian `UInt16` and `UInt32` reads;
- exact slices;
- no offset change after a failed read;
- explicit trailing-byte rejection.

All lengths originate in untrusted input. Check a length before adding offsets or allocating. The cursor's `remainingCount` avoids `offset + length` arithmetic until the range is known to fit.

## 3. CBOR attack surface

An attestation object is CBOR. The credential public key inside authenticator data is another CBOR value. A generic permissive decoder is educationally convenient but security-sensitive:

- indefinite lengths can create unbounded streams;
- deep nesting can exhaust the stack;
- declared lengths can trigger large allocations;
- duplicate map keys let different consumers choose different values;
- non-shortest encodings create alternative representations;
- non-canonical map order violates the deterministic form used by CTAP/WebAuthn.

`CBORDecoder` applies limits before allocation and accepts the deterministic subset needed by the course:

| Limit | Default |
| --- | ---: |
| entire CBOR input | 64 KiB |
| byte string | 32 KiB |
| text string | 8 KiB |
| collection entries | 256 |
| nesting depth | 16 |

It also exposes `decodePrefix`. Authenticator data does not give the COSE key a byte length; the decoder must parse exactly one value and report how many bytes it consumed before optional extension CBOR begins.

Exercise:

```sh
swift test --filter CBORTests
```

Add a test for a 257-entry array. Confirm rejection occurs before reserving 257 elements.

## 4. Authenticator data layout

Every authenticator data value begins with 37 bytes:

```text
offset  size  field
0       32    SHA-256(RP ID)
32      1     flags
33      4     signature counter, big-endian
37      ...   optional attested credential data and/or extensions
```

Flag bits in this course:

| Bit | Name | Meaning |
| ---: | --- | --- |
| 0 | UP | user presence result |
| 1 | reserved | must be zero |
| 2 | UV | user verification result |
| 3 | BE | credential is backup eligible |
| 4 | BS | credential is currently backed up |
| 5 | reserved | must be zero |
| 6 | AT | attested credential data follows |
| 7 | ED | extension CBOR follows |

The structural parser rejects reserved bits and BS without BE. Ceremony-specific policy is applied later: registration requires AT; authentication rejects AT; both require UP; UV depends on the issued options.

When AT is set, the layout continues:

```text
16 bytes       AAGUID
2 bytes        credential ID length, big-endian
N bytes        credential ID
one CBOR item  credentialPublicKey (COSE_Key)
```

## 5. COSE EC2 key

The ES256 public key is a CBOR map. Integer labels are part of COSE, not arbitrary application choices:

| Label | Meaning | Required value |
| ---: | --- | ---: |
| `1` | key type (`kty`) | `2` (EC2) |
| `3` | algorithm (`alg`) | `-7` (ES256) |
| `-1` | curve (`crv`) | `1` (P-256) |
| `-2` | x coordinate | 32-byte string |
| `-3` | y coordinate | 32-byte string |

Swift Crypto accepts an ANSI X9.63 uncompressed point:

```text
0x04 || x || y
```

The prefix is not part of either coordinate. `COSEEC2PublicKey.x963Representation` adds it only when constructing a verification key.

## 6. Attestation object

The registration response contains a CBOR map with:

- `fmt`: attestation format identifier;
- `authData`: raw authenticator data bytes;
- `attStmt`: format-specific statement map.

The lab requests and accepts only `fmt = "none"` with an empty statement. The public credential is still present inside `authData`; “none attestation” does not mean “no public key.” It means the RP is not requesting provenance evidence about the authenticator.

## Observe and break it

Run:

```sh
swift test --filter AuthenticatorDataTests
```

Then add one test for each mutation:

1. credential ID length is one byte longer than available input;
2. x coordinate is 31 bytes;
3. ED is set but no extension value follows;
4. one trailing byte exists after an assertion without ED;
5. a COSE map contains `alg = -257` instead of `-7`.

Do not “fix” the tests by ignoring input. Each case must produce a typed rejection.

## Completion criteria

- You can annotate a registration authenticator-data hex dump by offset.
- You can explain why raw client JSON is retained after decoding.
- You can explain duplicate-key and canonical-order rejection.
- You can convert a COSE EC2 key into X9.63 form without changing coordinates.
- All protocol primitive tests pass.
