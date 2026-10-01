//! Revocation sends the refresh token and never converts provider text into an error.

use serde::Serialize;
use zeroize::Zeroize;

use crate::{
    AuthFailureReason, AuthTransport, OpenAiAuthProfile, Result, SessionMaterial, TransportRequest,
    error::failure, provider,
};

pub struct RevokePlan {
    request: TransportRequest,
}

impl RevokePlan {
    /// Creates a revocation plan from an active session.
    ///
    /// # Errors
    /// Returns a canonical failure if the request cannot be represented safely.
    pub fn for_session(profile: &OpenAiAuthProfile, session: &SessionMaterial) -> Result<Self> {
        Self::for_token(profile, session.refresh_token())
    }

    /// Creates a revocation plan without requiring an active identity token.
    ///
    /// # Errors
    /// Returns a canonical failure if the request cannot be represented safely.
    pub fn for_refresh_token(
        profile: &OpenAiAuthProfile,
        material: &RevocationMaterial,
    ) -> Result<Self> {
        Self::for_token(profile, material.token())
    }

    fn for_token(profile: &OpenAiAuthProfile, token: &str) -> Result<Self> {
        let body = serde_json::to_vec(&RevokeRequest {
            token,
            token_type_hint: "refresh_token",
            client_id: profile.client_id(),
        })
        .map_err(|_| invalid())?;
        Ok(Self {
            request: TransportRequest::post(profile.revoke_endpoint(), "application/json", body),
        })
    }

    #[must_use]
    pub fn into_request(self) -> TransportRequest {
        self.request
    }
}

/// Revokes the refresh token associated with an active session.
///
/// # Errors
/// Returns a canonical transport or provider rejection.
pub async fn revoke_session(
    session: &SessionMaterial,
    profile: &OpenAiAuthProfile,
    transport: &impl AuthTransport,
) -> Result<()> {
    let response = transport
        .send(RevokePlan::for_session(profile, session)?.into_request())
        .await?;
    provider::accepted(&response, provider::Operation::Revoke)
}

pub struct RevocationMaterial {
    token: String,
}

impl RevocationMaterial {
    /// Creates an owned, zeroizing refresh token for logout recovery.
    ///
    /// # Errors
    /// Returns a canonical failure when the token is malformed.
    pub fn new(token: String) -> Result<Self> {
        crate::validation::secret(&token)?;
        Ok(Self { token })
    }

    fn token(&self) -> &str {
        &self.token
    }
}

impl Drop for RevocationMaterial {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

/// Revokes a refresh token even when its former identity token has expired.
///
/// # Errors
/// Returns a canonical transport or provider rejection.
pub async fn revoke_refresh_token(
    material: &RevocationMaterial,
    profile: &OpenAiAuthProfile,
    transport: &impl AuthTransport,
) -> Result<()> {
    let response = transport
        .send(RevokePlan::for_refresh_token(profile, material)?.into_request())
        .await?;
    provider::accepted(&response, provider::Operation::Revoke)
}

#[derive(Serialize)]
struct RevokeRequest<'a> {
    token: &'a str,
    token_type_hint: &'static str,
    client_id: &'a str,
}

fn invalid() -> crate::AuthFailure {
    failure(
        AuthFailureReason::InvalidPlan,
        false,
        "OpenAI revocation plan is invalid",
    )
}
