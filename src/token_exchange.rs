//! Authorization codes become verified session material through one typed exchange.

use serde::Deserialize;
use zeroize::Zeroize;

use crate::{
    AuthFailureReason, AuthTransport, Clock, JwtVerification, JwtVerifier, OpenAiAuthProfile,
    Result, SessionMaterial, TransportRequest, error::failure, provider,
    session_restore::validate_claims, validation::secret,
};

pub struct TokenExchangePlan {
    request: TransportRequest,
    nonce: Option<String>,
}

impl TokenExchangePlan {
    pub(crate) fn authorization_code(
        profile: &OpenAiAuthProfile,
        code: &str,
        callback_uri: &str,
        verifier: &str,
        nonce: Option<String>,
    ) -> Result<Self> {
        secret(code)?;
        secret(verifier)?;
        let body = crate::encoding::form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", callback_uri),
            ("client_id", profile.client_id()),
            ("code_verifier", verifier),
        ]);
        Ok(Self {
            request: TransportRequest::post(
                profile.token_endpoint(),
                "application/x-www-form-urlencoded",
                body,
            ),
            nonce,
        })
    }

    #[must_use]
    pub fn into_request(self) -> TransportRequest {
        self.request
    }

    pub(crate) async fn execute(
        self,
        profile: &OpenAiAuthProfile,
        transport: &impl AuthTransport,
        verifier: &impl JwtVerifier,
        clock: &impl Clock,
    ) -> Result<SessionMaterial> {
        let expected_nonce = self.nonce;
        let response = transport.send(self.request).await?;
        provider::accepted(&response, provider::Operation::Authorize)?;
        let mut wire: TokenWire = serde_json::from_slice(response.body()).map_err(|_| invalid())?;
        secret(&wire.id_token)?;
        secret(&wire.access_token)?;
        secret(&wire.refresh_token)?;
        let now = clock.unix_seconds()?;
        let claims = verifier
            .verify(JwtVerification::new(
                &wire.id_token,
                profile.issuer(),
                profile.client_id(),
                expected_nonce.as_deref(),
                now,
            ))
            .await?;
        validate_claims(profile, &claims, expected_nonce.as_deref(), now)?;
        SessionMaterial::create(
            std::mem::take(&mut wire.id_token),
            std::mem::take(&mut wire.access_token),
            std::mem::take(&mut wire.refresh_token),
            claims,
        )
    }
}

#[allow(clippy::struct_field_names)]
#[derive(Deserialize)]
struct TokenWire {
    id_token: String,
    access_token: String,
    refresh_token: String,
}

impl Drop for TokenWire {
    fn drop(&mut self) {
        self.id_token.zeroize();
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

fn invalid() -> crate::AuthFailure {
    failure(
        AuthFailureReason::InvalidResponse,
        false,
        "OpenAI token response was rejected",
    )
}
