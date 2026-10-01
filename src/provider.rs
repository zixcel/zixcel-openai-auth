//! Provider statuses collapse into stable failures without retaining response text.

use crate::{AuthFailureReason, Result, TransportResponse, error::failure};

#[derive(Clone, Copy)]
pub(crate) enum Operation {
    Authorize,
    Refresh,
    Revoke,
}

pub(crate) fn accepted(response: &TransportResponse, operation: Operation) -> Result<()> {
    let status = response.status();
    if (200..=299).contains(&status) {
        return Ok(());
    }
    let (reason, retryable, message) = if status == 429 {
        (
            AuthFailureReason::ProviderRateLimited,
            true,
            "OpenAI authorization was rate limited",
        )
    } else if status >= 500 {
        (
            AuthFailureReason::ProviderUnavailable,
            true,
            "OpenAI authorization is temporarily unavailable",
        )
    } else if matches!(operation, Operation::Refresh) {
        refresh_failure(response.body()).unwrap_or_else(|| rejected(operation))
    } else {
        rejected(operation)
    };
    Err(failure(reason, retryable, message))
}

fn rejected(operation: Operation) -> (AuthFailureReason, bool, &'static str) {
    match operation {
        Operation::Authorize => (
            AuthFailureReason::ProviderDenied,
            false,
            "OpenAI authorization was denied",
        ),
        Operation::Refresh => (
            AuthFailureReason::RefreshRejected,
            false,
            "OpenAI session refresh was rejected",
        ),
        Operation::Revoke => (
            AuthFailureReason::RevocationRejected,
            false,
            "OpenAI session revocation was rejected",
        ),
    }
}

fn refresh_failure(body: &[u8]) -> Option<(AuthFailureReason, bool, &'static str)> {
    const CASES: [(&[u8], AuthFailureReason, &str); 3] = [
        (
            b"\"refresh_token_expired\"",
            AuthFailureReason::RefreshTokenExpired,
            "OpenAI refresh token expired",
        ),
        (
            b"\"refresh_token_reused\"",
            AuthFailureReason::RefreshTokenReused,
            "OpenAI refresh token was already used",
        ),
        (
            b"\"refresh_token_invalidated\"",
            AuthFailureReason::RefreshTokenRevoked,
            "OpenAI refresh token was revoked",
        ),
    ];
    CASES.into_iter().find_map(|(pattern, reason, message)| {
        body.windows(pattern.len())
            .any(|window| window == pattern)
            .then_some((reason, false, message))
    })
}
