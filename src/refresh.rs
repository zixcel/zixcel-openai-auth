//! Refresh rotates returned credentials only after any new identity token is verified.

use serde::Serialize;

use crate::{
    AuthTransport, Clock, JwtVerification, JwtVerifier, OpenAiAuthProfile, Result, SessionMaterial,
    TransportRequest, provider, session_restore::validate_claims,
};

pub struct RefreshPlan {
    request: TransportRequest,
}

impl RefreshPlan {
    /// Creates a refresh plan from an already verified active session.
    ///
    /// # Errors
    /// Returns a canonical failure if the request cannot be represented safely.
    pub fn for_session(profile: &OpenAiAuthProfile, session: &SessionMaterial) -> Result<Self> {
        Self::for_token(profile, session.refresh_token())
    }

    pub(crate) fn for_token(profile: &OpenAiAuthProfile, refresh_token: &str) -> Result<Self> {
        let body = serde_json::to_vec(&RefreshRequest {
            client_id: profile.client_id(),
            grant_type: "refresh_token",
            refresh_token,
        })
        .map_err(|_| crate::refresh_wire::invalid())?;
        Ok(Self {
            request: TransportRequest::post(profile.token_endpoint(), "application/json", body),
        })
    }

    #[must_use]
    pub fn into_request(self) -> TransportRequest {
        self.request
    }
}

/// Atomically rotates an active session after verifying any new identity token.
///
/// # Errors
/// Returns a canonical failure without partially changing the active session.
pub async fn refresh_session(
    session: &mut SessionMaterial,
    profile: &OpenAiAuthProfile,
    transport: &impl AuthTransport,
    verifier: &impl JwtVerifier,
    clock: &impl Clock,
) -> Result<()> {
    let response = transport
        .send(RefreshPlan::for_session(profile, session)?.into_request())
        .await?;
    provider::accepted(&response, provider::Operation::Refresh)?;
    let mut wire = crate::refresh_wire::RefreshWire::parse(response.body())?;
    let identity = if let Some(id_token) = wire.id_token.as_deref() {
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
        Some((
            std::mem::take(&mut wire.id_token).ok_or_else(crate::refresh_wire::invalid)?,
            claims,
        ))
    } else {
        None
    };
    session.commit_refresh(
        std::mem::take(&mut wire.access_token),
        std::mem::take(&mut wire.refresh_token),
        identity,
    )
}

#[derive(Serialize)]
struct RefreshRequest<'a> {
    client_id: &'a str,
    grant_type: &'static str,
    refresh_token: &'a str,
}
