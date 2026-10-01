//! Verified claims are accepted only through the injected verifier boundary.

use std::{future::Future, pin::Pin};

use crate::{AuthFailureReason, Result, error::failure, validation::bounded_text};

pub type VerificationFuture<'a> = Pin<Box<dyn Future<Output = Result<VerifiedClaims>> + Send + 'a>>;

pub trait JwtVerifier: Send + Sync {
    fn verify<'a>(&'a self, request: JwtVerification<'a>) -> VerificationFuture<'a>;
}

#[derive(Clone, Copy)]
pub struct JwtVerification<'a> {
    token: &'a str,
    issuer: &'a str,
    audience: &'a str,
    nonce: Option<&'a str>,
    now: u64,
}

impl<'a> JwtVerification<'a> {
    pub(crate) const fn new(
        token: &'a str,
        issuer: &'a str,
        audience: &'a str,
        nonce: Option<&'a str>,
        now: u64,
    ) -> Self {
        Self {
            token,
            issuer,
            audience,
            nonce,
            now,
        }
    }

    #[must_use]
    pub const fn token(&self) -> &'a str {
        self.token
    }

    #[must_use]
    pub const fn issuer(&self) -> &'a str {
        self.issuer
    }

    #[must_use]
    pub const fn audience(&self) -> &'a str {
        self.audience
    }

    #[must_use]
    pub const fn nonce(&self) -> Option<&'a str> {
        self.nonce
    }

    #[must_use]
    pub const fn now(&self) -> u64 {
        self.now
    }
}

pub struct VerifiedClaims {
    pub(crate) issuer: String,
    pub(crate) audience: String,
    pub(crate) expires_at: u64,
    pub(crate) issued_at: u64,
    pub(crate) not_before: Option<u64>,
    pub(crate) nonce: Option<String>,
    pub(crate) email: Option<String>,
    pub(crate) plan_type: Option<String>,
    pub(crate) user_id: Option<String>,
    pub(crate) account_id: Option<String>,
    pub(crate) fedramp: bool,
}

impl VerifiedClaims {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn after_signature_verification(
        issuer: String,
        audience: String,
        expires_at: u64,
        issued_at: u64,
        not_before: Option<u64>,
        nonce: Option<String>,
        email: Option<String>,
        plan_type: Option<String>,
        user_id: Option<String>,
        account_id: Option<String>,
        fedramp: bool,
    ) -> Result<Self> {
        bounded_optional(email.as_deref(), 320)?;
        bounded_optional(plan_type.as_deref(), 64)?;
        bounded_optional(user_id.as_deref(), 128)?;
        bounded_optional(account_id.as_deref(), 128)?;
        bounded_optional(nonce.as_deref(), 128)?;
        Ok(Self {
            issuer,
            audience,
            expires_at,
            issued_at,
            not_before,
            nonce,
            email,
            plan_type,
            user_id,
            account_id,
            fedramp,
        })
    }
}

fn bounded_optional(value: Option<&str>, maximum: usize) -> Result<()> {
    value.map_or(Ok(()), |value| {
        bounded_text(value, maximum, "verified claim is invalid").map_err(|_| {
            failure(
                AuthFailureReason::TokenVerificationRejected,
                false,
                "verified token claims were rejected",
            )
        })
    })
}
