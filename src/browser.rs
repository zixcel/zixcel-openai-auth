//! Browser login owns one short-lived state, nonce, and PKCE ceremony.

use zeroize::Zeroize;

use crate::{
    AuthFailureReason, AuthTransport, BrowserAuthorizationPlan, BrowserCallback, Clock,
    JwtVerifier, OpenAiAuthProfile, RandomSource, Result, SessionMaterial, TokenExchangePlan,
    error::failure,
};

pub struct BrowserAttempt {
    authorization_url: String,
    callback_uri: String,
    state: String,
    nonce: String,
    verifier: String,
    callback_port: u16,
    expires_at: u64,
    used: bool,
}

impl BrowserAttempt {
    /// Creates a single-use browser authorization attempt.
    ///
    /// # Errors
    /// Returns a canonical failure when the port, clock, entropy, or profile is invalid.
    pub fn begin(
        profile: &OpenAiAuthProfile,
        callback_port: u16,
        random: &impl RandomSource,
        clock: &impl Clock,
    ) -> Result<Self> {
        let callback_uri = profile.callback_uri(callback_port)?;
        let state = crate::encoding::random_secret(random)?;
        let nonce = crate::encoding::random_secret(random)?;
        let (verifier, challenge) = crate::encoding::pkce(random)?;
        let authorization_url = crate::browser_plan::authorization_url(
            profile,
            &callback_uri,
            &state,
            &nonce,
            &challenge,
        )?;
        Ok(Self {
            authorization_url,
            callback_uri,
            state,
            nonce,
            verifier,
            callback_port,
            expires_at: clock.unix_seconds()?.saturating_add(10 * 60),
            used: false,
        })
    }

    #[must_use]
    pub fn authorization_plan(&self) -> BrowserAuthorizationPlan<'_> {
        BrowserAuthorizationPlan::new(&self.authorization_url, self.callback_port)
    }

    /// Exchanges a matching callback for verified session material.
    ///
    /// # Errors
    /// Returns a canonical failure for expiry, replay, mismatch, transport, or token rejection.
    pub async fn complete(
        &mut self,
        callback: BrowserCallback,
        profile: &OpenAiAuthProfile,
        transport: &impl AuthTransport,
        verifier: &impl JwtVerifier,
        clock: &impl Clock,
    ) -> Result<SessionMaterial> {
        if self.used {
            return Err(failure(
                AuthFailureReason::ReplayDetected,
                false,
                "login attempt was already consumed",
            ));
        }
        if clock.unix_seconds()? > self.expires_at {
            return Err(failure(
                AuthFailureReason::Expired,
                false,
                "login attempt expired",
            ));
        }
        if !crate::encoding::equal_secret(callback.state(), &self.state) {
            return Err(failure(
                AuthFailureReason::StateMismatch,
                false,
                "callback state did not match",
            ));
        }
        self.used = true;
        let plan = TokenExchangePlan::authorization_code(
            profile,
            callback.code(),
            &self.callback_uri,
            &self.verifier,
            Some(std::mem::take(&mut self.nonce)),
        )?;
        plan.execute(profile, transport, verifier, clock).await
    }
}

impl Drop for BrowserAttempt {
    fn drop(&mut self) {
        self.authorization_url.zeroize();
        self.callback_uri.zeroize();
        self.state.zeroize();
        self.nonce.zeroize();
        self.verifier.zeroize();
    }
}
