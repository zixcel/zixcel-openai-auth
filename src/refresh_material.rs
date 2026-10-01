//! Expired signed identity tokens may anchor refresh without becoming active sessions.

use zeroize::Zeroize;

use crate::{
    AccountProjection, AuthFailureReason, AuthTransport, Clock, JwtVerification, JwtVerifier,
    OpenAiAuthProfile, RefreshPlan, Result, SessionMaterial,
    error::failure,
    provider,
    session_restore::{validate_claims, validate_refresh_anchor},
    validation::secret,
};

pub struct RefreshMaterial {
    refresh_token: String,
    projection: AccountProjection,
}

impl RefreshMaterial {
    fn new(refresh_token: String, claims: crate::VerifiedClaims) -> Result<Self> {
        secret(&refresh_token)?;
        if !AccountProjection::claims_have_stable_identity(&claims) {
            return Err(failure(
                AuthFailureReason::ClaimsBindingMismatch,
                false,
                "stored identity has no stable account identifier",
            ));
        }
        Ok(Self {
            refresh_token,
            projection: AccountProjection::from_claims(claims),
        })
    }
}

/// Verifies an expired signed identity as a non-active refresh anchor.
///
/// # Errors
/// Returns a canonical failure for malformed secrets, signatures, or claim binding.
pub async fn restore_refresh_material(
    id_token: String,
    refresh_token: String,
    profile: &OpenAiAuthProfile,
    verifier: &impl JwtVerifier,
    clock: &impl Clock,
) -> Result<RefreshMaterial> {
    secret(&id_token)?;
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
    validate_refresh_anchor(profile, &claims, now)?;
    RefreshMaterial::new(refresh_token, claims)
}

/// Rotates a stored refresh anchor into a newly verified active session.
///
/// # Errors
/// Returns a canonical failure unless a matching active identity and access token are returned.
pub async fn refresh_stored_session(
    mut material: RefreshMaterial,
    profile: &OpenAiAuthProfile,
    transport: &impl AuthTransport,
    verifier: &impl JwtVerifier,
    clock: &impl Clock,
) -> Result<SessionMaterial> {
    let response = transport
        .send(RefreshPlan::for_token(profile, &material.refresh_token)?.into_request())
        .await?;
    provider::accepted(&response, provider::Operation::Refresh)?;
    let mut wire = crate::refresh_wire::RefreshWire::parse(response.body())?;
    let id_token = wire.id_token.as_deref().ok_or_else(missing_identity)?;
    wire.access_token.as_deref().ok_or_else(missing_identity)?;
    let now = clock.unix_seconds()?;
    let claims = verifier
        .verify(JwtVerification::new(
            id_token,
            profile.issuer(),
            profile.client_id(),
            None,
            now,
        ))
        .await?;
    validate_claims(profile, &claims, None, now)?;
    if !material.projection.same_identity(&claims) {
        return Err(failure(
            AuthFailureReason::ClaimsBindingMismatch,
            false,
            "refreshed identity does not match stored custody",
        ));
    }
    let id_token = std::mem::take(&mut wire.id_token).ok_or_else(missing_identity)?;
    let access_token = std::mem::take(&mut wire.access_token).ok_or_else(missing_identity)?;
    let refresh_token = std::mem::take(&mut wire.refresh_token)
        .unwrap_or_else(|| std::mem::take(&mut material.refresh_token));
    SessionMaterial::create(id_token, access_token, refresh_token, claims)
}

fn missing_identity() -> crate::AuthFailure {
    failure(
        AuthFailureReason::InvalidResponse,
        false,
        "refresh did not return an active OpenAI identity",
    )
}

impl Drop for RefreshMaterial {
    fn drop(&mut self) {
        self.refresh_token.zeroize();
    }
}
