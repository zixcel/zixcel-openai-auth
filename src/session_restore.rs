//! Restoring custody material repeats signature and account binding verification.

use crate::{
    AuthFailureReason, Clock, JwtVerification, JwtVerifier, OpenAiAuthProfile, Result,
    SessionMaterial, VerifiedClaims, error::failure, validation::secret,
};

/// Re-verifies active credentials moved back from a product-owned custodian.
///
/// # Errors
/// Returns a canonical failure for malformed secrets, signatures, expiry, or claim binding.
pub async fn restore_session(
    id_token: String,
    access_token: String,
    refresh_token: String,
    profile: &OpenAiAuthProfile,
    verifier: &impl JwtVerifier,
    clock: &impl Clock,
) -> Result<SessionMaterial> {
    secret(&id_token)?;
    secret(&access_token)?;
    secret(&refresh_token)?;
    let now = clock.unix_seconds()?;
    let claims = verifier
        .verify(JwtVerification::new(
            &id_token,
            profile.issuer(),
            profile.client_id(),
            None,
            now,
        ))
        .await?;
    validate_claims(profile, &claims, None, now)?;
    SessionMaterial::create(id_token, access_token, refresh_token, claims)
}

pub(crate) fn validate_claims(
    profile: &OpenAiAuthProfile,
    claims: &VerifiedClaims,
    expected_nonce: Option<&str>,
    now: u64,
) -> Result<()> {
    if claims.issuer != profile.issuer()
        || claims.audience != profile.client_id()
        || claims.expires_at <= now
        || claims.expires_at > now.saturating_add(24 * 60 * 60)
        || claims.issued_at > now.saturating_add(60)
        || claims.issued_at.saturating_add(24 * 60 * 60) < now
        || claims.expires_at > claims.issued_at.saturating_add(24 * 60 * 60)
        || claims
            .not_before
            .is_some_and(|value| value > now.saturating_add(60))
    {
        return Err(binding_failure());
    }
    match expected_nonce {
        Some(expected)
            if claims
                .nonce
                .as_deref()
                .is_some_and(|actual| crate::encoding::equal_secret(actual, expected)) => {}
        Some(_) => return Err(binding_failure()),
        None => {}
    }
    if !profile.workspace_allowed(claims.account_id.as_deref()) {
        return Err(failure(
            AuthFailureReason::WorkspaceRejected,
            false,
            "OpenAI account is outside the approved workspace",
        ));
    }
    Ok(())
}

pub(crate) fn validate_refresh_anchor(
    profile: &OpenAiAuthProfile,
    claims: &VerifiedClaims,
    now: u64,
) -> Result<()> {
    if claims.issuer != profile.issuer()
        || claims.audience != profile.client_id()
        || claims.issued_at > now.saturating_add(60)
        || claims.expires_at <= claims.issued_at
        || claims.expires_at > claims.issued_at.saturating_add(24 * 60 * 60)
        || claims
            .not_before
            .is_some_and(|value| value > now.saturating_add(60))
    {
        return Err(binding_failure());
    }
    if !profile.workspace_allowed(claims.account_id.as_deref()) {
        return Err(failure(
            AuthFailureReason::WorkspaceRejected,
            false,
            "OpenAI account is outside the approved workspace",
        ));
    }
    Ok(())
}

fn binding_failure() -> crate::AuthFailure {
    failure(
        AuthFailureReason::ClaimsBindingMismatch,
        false,
        "verified token claims do not match this authorization request",
    )
}
