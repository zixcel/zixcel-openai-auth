# zixcel-openai-auth

Transport-independent `OpenAI` account authorization core with typed browser/device plans, JWT verification, refresh and revocation. Use this crate to implement product-owned account login while injecting network access, time, randomness and credential custody.

## Install

```toml
[dependencies]
zixcel-openai-auth = "0.10.0"
```

This dependency uses crates.io; no private registry is required.

## Capabilities

- Prepare browser authorization and device-code exchanges.
- Verify token context against explicit profile, keys and time.
- Restore refresh material, refresh sessions and construct revocation requests.

## Example

```rust
use zixcel_openai_auth::OpenAiAuthProfile;

let _profile = OpenAiAuthProfile::codex_managed();
```

## Features and requirements

Requires Rust 1.95 or newer. Other release candidates in this batch require Rust 1.97 or newer.

## Boundaries

This crate owns no HTTP client, browser launcher, callback listener, OS keyring or persistence format. `SessionMaterial` contains secrets and must not enter web APIs, JSON, logs or telemetry. Local protocol tests do not certify a live provider login.

## Development

```sh
cargo fmt --all -- --check
cargo test --locked --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
```

## Documentation and license

[API documentation](https://docs.rs/zixcel-openai-auth) · [Source](https://github.com/zixcel/zixcel-openai-auth) · [Usage guide](https://github.com/zixcel/zixcel-openai-auth/blob/main/docs/getting-started.md)

Apache-2.0. Retain the package LICENSE and NOTICE; see the source repository for security reporting and contribution guidelines.

## Authorization egress policy

`OpenAiAuthorizationEgress` validates managed authorization requests before an
injected transport sends them. Only the production HTTPS origin, known methods,
paths and content types are accepted. User information, query parameters, fragments
and nonstandard ports are rejected. Request and response admission is limited to
64 KiB. The adapter must also bound streaming reads and enforce a deadline.

This policy performs no network access, secret storage or account operation.
Provider-specific policy belongs to Zixcel; generic transport remains a caller port.
