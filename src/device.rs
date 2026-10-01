//! Device login exposes only the verification URL and one-time user code.

use zeroize::Zeroize;

use crate::{
    AuthFailureReason, AuthTransport, Clock, DevicePollPlan, JwtVerifier, OpenAiAuthProfile,
    Result, SessionMaterial, TokenExchangePlan, error::failure, provider, validation,
};

pub struct DeviceAttempt {
    verification_url: String,
    user_code: String,
    device_auth_id: String,
    interval: u64,
    next_poll_at: u64,
    expires_at: u64,
    used: bool,
}

impl DeviceAttempt {
    pub(crate) fn new(
        verification_url: String,
        user_code: String,
        device_auth_id: String,
        interval: u64,
        now: u64,
    ) -> Self {
        Self {
            verification_url,
            user_code,
            device_auth_id,
            interval,
            next_poll_at: now,
            expires_at: now.saturating_add(15 * 60),
            used: false,
        }
    }

    #[must_use]
    pub fn verification_url(&self) -> &str {
        &self.verification_url
    }

    #[must_use]
    pub fn user_code(&self) -> &str {
        &self.user_code
    }

    #[must_use]
    pub const fn poll_interval_seconds(&self) -> u64 {
        self.interval
    }

    /// Executes at most one eligible device poll and token exchange.
    ///
    /// # Errors
    /// Returns a canonical failure for expiry, replay, PKCE, transport, or token rejection.
    pub async fn poll(
        &mut self,
        profile: &OpenAiAuthProfile,
        transport: &impl AuthTransport,
        verifier: &impl JwtVerifier,
        clock: &impl Clock,
    ) -> Result<DevicePollState> {
        if self.used {
            return Err(failure(
                AuthFailureReason::ReplayDetected,
                false,
                "device login was consumed",
            ));
        }
        let now = clock.unix_seconds()?;
        if now > self.expires_at {
            return Err(failure(
                AuthFailureReason::Expired,
                false,
                "device login expired",
            ));
        }
        if now < self.next_poll_at {
            return Ok(DevicePollState::Pending {
                retry_after_seconds: self.next_poll_at - now,
            });
        }
        self.next_poll_at = now.saturating_add(self.interval);
        let plan = DevicePollPlan::new(profile, &self.device_auth_id, &self.user_code)?;
        let response = transport.send(plan.into_request()).await?;
        if matches!(response.status(), 403 | 404) {
            return Ok(DevicePollState::Pending {
                retry_after_seconds: self.interval,
            });
        }
        provider::accepted(&response, provider::Operation::Authorize)?;
        self.used = true;
        let code: crate::device_wire::CodeWire =
            serde_json::from_slice(response.body()).map_err(|_| crate::device_wire::invalid())?;
        validation::secret(&code.authorization_code)?;
        validation::secret(&code.code_verifier)?;
        if !validation::base64url(&code.code_challenge)
            || !crate::encoding::equal_secret(
                &code.code_challenge,
                &crate::encoding::challenge(&code.code_verifier),
            )
        {
            return Err(failure(
                AuthFailureReason::PkceMismatch,
                false,
                "device PKCE proof failed",
            ));
        }
        let plan = TokenExchangePlan::authorization_code(
            profile,
            &code.authorization_code,
            &profile.device_callback_uri(),
            &code.code_verifier,
            None,
        )?;
        Ok(DevicePollState::Authorized(
            plan.execute(profile, transport, verifier, clock).await?,
        ))
    }
}

pub enum DevicePollState {
    Pending { retry_after_seconds: u64 },
    Authorized(SessionMaterial),
}

impl Drop for DeviceAttempt {
    fn drop(&mut self) {
        self.verification_url.zeroize();
        self.user_code.zeroize();
        self.device_auth_id.zeroize();
    }
}
