# Security policy

This crate is neither a credential custodian nor an identity provider. OpenAI OAuth tokens must remain within the consumer process; persistence requires transfer to a separately approved custody port.

## Requirements

- The only production issuer is `https://auth.openai.com`.
- Browser flows use independent 256-bit state, nonce and PKCE verifier.
- Consume callback state once; never reuse it after failure.
- Verify RS256 signatures, non-duplicated signing JWKS, strict headers, issuer, audience, `iat`, expiry and browser nonce.
- Recheck `exp`, `iat` and `nbf` against an injected trusted clock instead of jsonwebtoken's system clock. JWT decode disables time validation while retaining signature, issuer and audience validation.
- Compare state, nonce and PKCE using constant-time primitives.
- Bound provider-response reads and exclude raw bodies, queries and tokens from errors/logs.
- Consumers expose only authorization URLs and device user codes to UI, never other secrets.
- Do not bypass normal `restore_session` when active ID tokens expire. `RefreshMaterial` contains only the signed identity anchor and refresh token; promote it to `SessionMaterial` only after verifying new ID/access tokens and matching user/account.
- Logout recovery uses only `RevocationMaterial`, never impersonating an active identity.

Do not include tokens, authorization codes, callback URL queries or real account IDs in vulnerability reports. Use synthetic reproduction fixtures only.

## Common OSS security reporting


## Reporting a vulnerability

Use this repository's Security tab and **Report a vulnerability** to submit a private
report to maintainers. Do not open a public issue or pull request containing exploit
details, credentials, customer data, or personal information. If private reporting
is unavailable, use GitHub's private security-support channel and request a private
reporting route before disclosing details.

Include affected versions, a minimal synthetic reproduction, expected and observed
behavior, and impact. Remove real secrets and identifying data. Maintainers assess
the report and coordinate a correction and disclosure. No response-time guarantee,
bounty, or support contract is implied.

## Supported versions

The current main branch is maintained during development. Released-version support
is stated in release notes; older releases are not implicitly supported. Do not infer
runtime safety from a source scan or a passing CI policy check. Dependencies,
deployments, history, and application-specific authorization require their own checks.
