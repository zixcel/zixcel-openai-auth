//! JWKS acquisition is a bounded typed plan executed only by the injected transport.

use std::collections::BTreeSet;

use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse};

use crate::{
    AuthFailureReason, AuthTransport, OpenAiAuthProfile, Result, TransportRequest, error::failure,
};

pub struct JwksRequestPlan {
    request: TransportRequest,
}

impl JwksRequestPlan {
    #[must_use]
    pub fn for_profile(profile: &OpenAiAuthProfile) -> Self {
        Self {
            request: TransportRequest::get(profile.jwks_endpoint()),
        }
    }

    #[must_use]
    pub fn into_request(self) -> TransportRequest {
        self.request
    }
}

/// Acquires and validates the bounded managed signing-key set.
///
/// # Errors
/// Returns a canonical failure for transport, status, JSON, or key-policy rejection.
pub async fn fetch_openai_jwt_verifier(
    profile: &OpenAiAuthProfile,
    transport: &impl AuthTransport,
) -> Result<crate::OpenAiJwtVerifier> {
    let response = transport
        .send(JwksRequestPlan::for_profile(profile).into_request())
        .await?;
    if response.status() != 200 {
        return Err(failure(
            AuthFailureReason::ProviderUnavailable,
            true,
            "OpenAI signing keys are unavailable",
        ));
    }
    let keys: JwkSet = serde_json::from_slice(response.body()).map_err(|_| invalid_keys())?;
    if !valid_keys(&keys) {
        return Err(invalid_keys());
    }
    Ok(crate::OpenAiJwtVerifier::new(keys))
}

fn valid_keys(set: &JwkSet) -> bool {
    if set.keys.is_empty() || set.keys.len() > 16 {
        return false;
    }
    let mut ids = BTreeSet::new();
    set.keys.iter().all(|key| {
        let Some(id) = key.common.key_id.as_deref() else {
            return false;
        };
        crate::validation::opaque_identifier(id, 128)
            && ids.insert(id)
            && matches!(key.algorithm, AlgorithmParameters::RSA(_))
            && key
                .common
                .public_key_use
                .as_ref()
                .is_none_or(|value| *value == PublicKeyUse::Signature)
            && key
                .common
                .key_algorithm
                .is_none_or(|value| value == KeyAlgorithm::RS256)
            && key
                .common
                .key_operations
                .as_ref()
                .is_none_or(|values| values.len() == 1 && values[0] == KeyOperations::Verify)
    })
}

fn invalid_keys() -> crate::AuthFailure {
    failure(
        AuthFailureReason::TokenVerificationRejected,
        false,
        "OpenAI signing keys were rejected",
    )
}
