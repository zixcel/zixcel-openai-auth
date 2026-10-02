# Using zixcel-openai-auth

Compose OpenAI account authorization through an injected transport and explicit validation boundaries.

## Before you start

The caller supplies the transport, verifier and credential storage. Successful protocol validation is not evidence of a live provider deployment.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Prepare and validate the authorization ceremony.
- Verify returned token context through caller-provided trust and time.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
