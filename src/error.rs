//! Canonical failures prevent provider text from becoming application state.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, AuthFailure>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AuthFailureReason {
    InvalidProfile,
    RandomUnavailable,
    ClockUnavailable,
    InvalidPlan,
    TransportUnavailable,
    ResponseTooLarge,
    ProviderDenied,
    ProviderRateLimited,
    ProviderUnavailable,
    InvalidResponse,
    StateMismatch,
    ReplayDetected,
    PkceMismatch,
    TokenVerificationRejected,
    ClaimsBindingMismatch,
    WorkspaceRejected,
    Pending,
    Expired,
    RefreshTokenExpired,
    RefreshTokenReused,
    RefreshTokenRevoked,
    RefreshRejected,
    RevocationRejected,
}

#[derive(Debug, Error, Eq, PartialEq)]
#[error("{message}")]
pub struct AuthFailure {
    reason: AuthFailureReason,
    retryable: bool,
    message: &'static str,
}

impl AuthFailure {
    #[must_use]
    pub const fn new(reason: AuthFailureReason, retryable: bool, message: &'static str) -> Self {
        Self {
            reason,
            retryable,
            message,
        }
    }

    #[must_use]
    pub const fn reason(&self) -> AuthFailureReason {
        self.reason
    }

    #[must_use]
    pub const fn retryable(&self) -> bool {
        self.retryable
    }

    #[must_use]
    pub const fn safe_message(&self) -> &'static str {
        self.message
    }
}

pub(crate) fn failure(
    reason: AuthFailureReason,
    retryable: bool,
    message: &'static str,
) -> AuthFailure {
    AuthFailure::new(reason, retryable, message)
}
