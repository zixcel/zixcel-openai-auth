//! Concrete verification validates RS256 signatures before projecting any `OpenAI` claims.

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, jwk::JwkSet};
use serde::Deserialize;

use crate::{
    AuthFailureReason, JwtVerification, JwtVerifier, Result, VerificationFuture, VerifiedClaims,
    error::failure,
};

pub struct OpenAiJwtVerifier {
    keys: JwkSet,
}

impl OpenAiJwtVerifier {
    pub(crate) const fn new(keys: JwkSet) -> Self {
        Self { keys }
    }

    fn verify_token(&self, request: JwtVerification<'_>) -> Result<VerifiedClaims> {
        let header = crate::jwt_header::strict_header(request.token())?;
        let kid = header.kid.as_str();
        let key = self.keys.find(kid).ok_or_else(rejected)?;
        let decoding_key = DecodingKey::from_jwk(key).map_err(|_| rejected())?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[request.issuer()]);
        validation.set_audience(&[request.audience()]);
        validation.required_spec_claims = ["exp", "iss", "aud"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        validation.validate_exp = false;
        let claims = decode::<Claims>(request.token(), &decoding_key, &validation)
            .map_err(|_| rejected())?
            .claims;
        let audience = claims
            .aud
            .matching(request.audience())
            .ok_or_else(rejected)?;
        if let Some(expected) = request.nonce() {
            let Some(actual) = claims.nonce.as_deref() else {
                return Err(rejected());
            };
            if !crate::encoding::equal_secret(actual, expected) {
                return Err(rejected());
            }
        }
        let auth = claims.auth.unwrap_or_default();
        VerifiedClaims::after_signature_verification(
            claims.iss,
            audience,
            claims.exp,
            claims.iat,
            claims.nbf,
            claims.nonce,
            claims
                .email
                .or_else(|| claims.profile.and_then(|value| value.email)),
            auth.plan_type,
            auth.chatgpt_user_id.or(auth.user_id),
            auth.account_id,
            auth.fedramp,
        )
    }
}

impl JwtVerifier for OpenAiJwtVerifier {
    fn verify<'a>(&'a self, request: JwtVerification<'a>) -> VerificationFuture<'a> {
        Box::pin(async move { self.verify_token(request) })
    }
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: Audience,
    exp: u64,
    iat: u64,
    nbf: Option<u64>,
    nonce: Option<String>,
    email: Option<String>,
    #[serde(rename = "https://api.openai.com/profile")]
    profile: Option<ProfileClaims>,
    #[serde(rename = "https://api.openai.com/auth")]
    auth: Option<AuthClaims>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn matching(self, expected: &str) -> Option<String> {
        match self {
            Self::One(value) if value == expected => Some(value),
            Self::Many(values) if values.iter().any(|value| value == expected) => {
                Some(expected.to_owned())
            }
            Self::One(_) | Self::Many(_) => None,
        }
    }
}

#[derive(Deserialize)]
struct ProfileClaims {
    email: Option<String>,
}

#[derive(Default, Deserialize)]
struct AuthClaims {
    #[serde(rename = "chatgpt_plan_type")]
    plan_type: Option<String>,
    chatgpt_user_id: Option<String>,
    user_id: Option<String>,
    #[serde(rename = "chatgpt_account_id")]
    account_id: Option<String>,
    #[serde(rename = "chatgpt_account_is_fedramp", default)]
    fedramp: bool,
}

pub(crate) fn rejected() -> crate::AuthFailure {
    failure(
        AuthFailureReason::TokenVerificationRejected,
        false,
        "OpenAI identity token verification failed",
    )
}
