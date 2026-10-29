# Protocols and trust boundaries

The source of truth is `backend/app/api/`, `auth/dependencies.py`, and the corresponding agent transport. OpenAPI is served at `/api/docs`, with the schema at `/api/openapi.json`. Application endpoints use `/api/v1`.

## Browser requests

Login checks the configured `PUBLIC_ORIGIN`, verifies the password with Argon2, and verifies TOTP when configured. The browser receives a `Secure`, `HttpOnly`, `SameSite=Strict` session cookie with path `/api`. The database stores the hash of the opaque session token.

Mutations require both:

```text
Origin: exact PUBLIC_ORIGIN
X-CSRF-Token: session's CSRF value
```

Permission checks are server-side. `owner`, `operator`, `viewer`, and `deployer` are administrator roles; they are unrelated to endpoint classes such as `ADMINISTRATOR`. Privileged actions require MFA within the last ten minutes. Sessions expire after eight hours; a TOTP time step cannot be reused for another successful verification.

`frontend/src/api/client.ts` sends credentials and CSRF. Do not implement separate ad hoc fetch helpers that omit those controls.

## Device request signatures

This is certificate-based application authentication over verified HTTPS. **The current implementation is not transport-level mutual TLS.** It does not trust a browser-supplied or reverse-proxy-supplied identity header without a signature.

Each authenticated request has:

| Header | Contents |
|---|---|
| `X-Device-Certificate` | Lowercase SHA-256 fingerprint of the enrolled certificate's DER bytes |
| `X-Device-Time` | Unix timestamp in seconds |
| `X-Device-Nonce` | New random request identifier, 32–128 characters |
| `X-Device-Signature` | Base64 RSA PKCS#1 v1.5 / SHA-256 signature of the message below |

The exact UTF-8 message is:

```text
METHOD\n
/api/v1/target?query-if-present\n
UNIX_SECONDS\n
NONCE\n
lowercase_sha256_of_exact_request_body
```

The displayed `\n` markers mean one newline each; there is no extra newline after the body hash. GET requests normally hash an empty byte string. A query string is part of the signed target, so changing an upload offset or query invalidates the signature. Header names are case-insensitive.

Verification checks the credential's expiry/revocation, the device's enabled state, timestamp skew within 90 seconds, nonce length, signature, and nonce uniqueness. Nonces expire after five minutes. Endpoints need accurate local time; an offline LAN time source should be available.

### Debugging signature failures

Compare the five signed fields on both sides using non-secret test fixtures. Common causes are signing decoded JSON instead of transmitted bytes, including a trailing newline, dropping `/api/v1`, changing query order, or the machine clock being wrong. Do not disable certificate verification or log private keys to diagnose a failure.

## Signed server documents

Policies, deployment manifests and maintenance instructions share this outer shape:

```json
{
  "algorithm": "RS256",
  "payload": "BASE64_OF_EXACT_UTF8_JSON_BYTES",
  "signature": "BASE64_RSA_SIGNATURE"
}
```

The server uses stable JSON serialization before signing. The client **verifies the decoded payload bytes directly**, then parses them. Cross-language JSON reserialization can change property order, whitespace or Unicode escaping; it must not occur before verification.

Policy payloads include `device_id`, `version_id`, `revision`, `mode`, `valid_until` and `document`. Manifests include their device/job/task binding, schema and expiration. A valid signature on a document for another device is still rejected.

The policy public key is provisioned through a trusted local installation channel. Fetching an untrusted public key from the same response and accepting it would defeat signing.

## Policy synchronization and ETags

The ETag combines the assigned version UUID and device revision. `304 Not Modified` avoids transferring the document again. The agent clears its ETag near the signed envelope's expiry so it can obtain a renewed envelope even when policy content has not changed.

The version identifies immutable policy content. The revision additionally detects device-level changes such as mode or synchronization requests. A rollback creates a new policy version and increasing revision, so the client can refuse an old replay without preventing an authorized rollback.

## Evidence intake

Each check has an expected source: `agent`, `network`, or `server`. The server rejects network checks on the agent reporting route and overwrites agent-provided freshness/version/source fields at receipt.

An individual evaluation result includes:

```json
{
  "check_id": "firewall.enabled",
  "expected": true,
  "actual": true,
  "status": "PASS",
  "severity": "critical",
  "source": "agent",
  "verified_at": "UTC_ISO_TIME",
  "evidence": {},
  "remediation_eligible": true,
  "remediation_result": null,
  "error": null
}
```

`PASS` means that this source supplied acceptable fresh evidence for this check and policy version. It is not an attestation that the entire operating system is uncompromised.

## Large file transfer

1. An MFA-authorized uploader supplies package metadata, expected size and SHA-256.
2. The server creates an upload UUID or returns the existing content-addressed package.
3. Chunks are written with an exact expected offset. An out-of-order offset is a conflict, not an append.
4. Completion hashes the file and publishes it under its SHA-256 object name.
5. Package approval is separate from upload completion.
6. An authorized running deployment permits the target agent to download that package.

Downloads accept a single byte range. The agent verifies range position, total size, SHA-256 and publisher signature. The default server upload chunk is 4 MiB; the default download throttle is 2 MiB/s per response. Global deployment concurrency bounds ordinary agent transfers, but the current API has no separate global byte-rate limiter.

## SSH WebSocket

The browser first creates an authorized SSH session through an ordinary CSRF-protected API request. The returned ticket is short-lived and sent as the first WebSocket message, not as a URL query parameter. The broker checks the browser session, permission, MFA, origin, ticket, device eligibility and configured pinned host key.

The WebSocket then carries terminal text. Input and output are recorded as encrypted frames. The current terminal supports a fixed initial terminal size; dynamic resize, file transfer auditing and complete command attribution are not implemented. [Privileged operations](privileged-operations.md) explains the limits.

## Errors and limits

Errors use `{"error":{"code":"stable.code"}}`; validation errors may include field paths but never echo passwords, tokens or private keys. Request bodies, rate counters, file sizes, package arguments and terminal recording sizes are bounded. The application rate limiter is process-local; it is not a distributed brute-force defense.
