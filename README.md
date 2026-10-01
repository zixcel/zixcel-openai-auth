# zixcel-openai-auth

A Rust library separating OpenAI ChatGPT/Codex account authorization ceremonies from product UI, HTTP clients and credential stores. Consumers inject transport, clock and randomness and supply `OpenAiJwtVerifier` after obtaining JWKS.

## Boundaries

- Production enters only through `OpenAiAuthProfile::codex_managed()`, pinning issuer, public client, endpoints, scopes, originator and loopback callback port `1455` used by official Codex.
- Generate typed plans for Browser Authorization Code + PKCE, Device Code, refresh and revocation.
- No HTTP client, browser launcher, callback listener, thread/session database or OS keyring implementation.
- Tokens exist only in `SessionMaterial` and secret-bearing plans; no Debug, Clone or Serialize, and zeroization on drop.
- No API decodes unverified JWT payloads. The concrete verifier checks RS256, `kid`, JWKS policy, signature, issuer, audience, `iat`, expiry and browser nonce.
- No token injection route from browser/UI such as `chatgptAuthTokens` is provided.

## Usage model

```text
product UI -> product-owned login orchestration
             -> zixcel-openai-auth typed plan
             -> Crowsi-authorized provider egress
             -> injected JWT verifier
             -> process-local SessionMaterial
             -> Crowsi persistent custody
```

Only `AccountProjection` is displayable non-secret information. Never send `SessionMaterial` through web APIs, JSON, logs or telemetry.

## Consumer integration

```rust,ignore
let profile = OpenAiAuthProfile::codex_managed();
let verifier = fetch_openai_jwt_verifier(&profile, &transport).await?;
let mut attempt = BrowserAttempt::begin(&profile, 1455, &random, &clock)?;
open_browser(attempt.authorization_plan().url())?;
let session = attempt
    .complete(BrowserCallback::new(code, state)?, &profile, &transport, &verifier, &clock)
    .await?;
let custody = session.into_custody_parts();
```

`restore_refresh_material` verifies stored credentials with expired active ID tokens as signed identity anchors; `refresh_stored_session` promotes them to new active sessions. Logout uses `RevocationMaterial` without restoring expired ID tokens as active sessions.

The crate owns no HTTP, browser, callback listener, OS keyring or persistence format. Hatter may initiate CLI/Console authentication and display loopback details; this crate owns OpenAI protocol, while Crowsi owns provider egress and persistent custody. Consumers temporarily receiving `SessionMaterial` must immediately transfer it to Crowsi custody without exposing it through web, JSON, logs, telemetry or custom persistence formats.

## Verification

Checks use mock ports only, with no external communication.

```bash
cargo test --locked --offline
cargo clippy --locked --offline --lib -- -D warnings
node scripts/verify-msrv.mjs
node scripts/verify-source-size.mjs
```

Consumers pin `=0.1.1` and its release digest in the approved `zixcel-private` registry. Local paths, Git sources and arbitrary issuer/client-ID overrides are outside the release contract.

## Package integration

The package is an independently consumable unit. Callers reference its documented
interface through a versioned dependency and own application-specific composition
and integration.
