# HTTP API Reference

All JSON endpoints use `Content-Type: application/json`. Binary WebAuthn fields are unpadded Base64url strings. Responses include `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, and `X-Request-ID`.

The lab closes each HTTP/1.1 connection after one response. Production may use a different transport adapter without changing domain verification.

## Health

```http
GET /healthz
```

```json
{"status":"ok"}
```

This is a process health signal, not proof that external storage, AASA, or a complete ceremony is healthy.

## Apple app-site association

```http
GET /.well-known/apple-app-site-association
```

```json
{"webcredentials":{"apps":["TEAMID.com.example.PasskeyLab"]}}
```

Serve over the public HTTPS RP host without redirect.

## Begin registration

```http
POST /v1/passkeys/registration/options
Content-Type: application/json

{"username":"alice@example.com","displayName":"Alice"}
```

Returns `RegistrationOptionsResponse`: ceremony ID plus public-key creation options. No account is committed yet.

## Complete registration

```http
POST /v1/passkeys/registration/complete
Content-Type: application/json
```

Body: `CompleteRegistrationRequest`, including credential ID, raw client data, and attestation object.

Success: 201 with account summary and credential ID. The account and first credential were committed atomically.

## Begin authentication

```http
POST /v1/passkeys/authentication/options
Content-Type: application/json

{}
```

The optional body field `username` requests a username-hinted flow. Omit it for discoverable Passkey account selection.

## Complete authentication

```http
POST /v1/passkeys/authentication/complete
Content-Type: application/json
```

Body: `CompleteAuthenticationRequest`, including credential ID, raw client data, authenticator data, DER signature, and user handle.

Success: 200 with account summary, application session bearer, and ISO-8601 expiry.

## Current user

```http
GET /v1/me
Authorization: Bearer <session-token>
```

Returns the authenticated account summary.

## Logout

```http
POST /v1/session/logout
Authorization: Bearer <session-token>
```

Returns 204 and revokes only the presented application session.

## Public errors

```json
{
  "code": "invalid_ceremony",
  "message": "The ceremony is invalid or expired.",
  "requestID": "..."
}
```

Common codes:

| Status | Code | Meaning |
| ---: | --- | --- |
| 400 | `invalid_request` | malformed JSON/encoding/input |
| 400 | `invalid_ceremony` | unknown, expired, used, or wrong-purpose ceremony |
| 400 | `invalid_registration` | registration verification failed |
| 401 | `unauthorized` | assertion/session/account binding failed |
| 404 | `not_found` | unknown endpoint |
| 409 | `username_unavailable` | username cannot be used |
| 413 | `body_too_large` | body exceeded 64 KiB |
| 500 | `internal_error` | unhandled server/storage failure |

Precise verifier errors are not exposed. Correlate the request ID with protected internal telemetry.
