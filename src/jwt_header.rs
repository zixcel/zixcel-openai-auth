//! JWT headers are parsed with a deny-unknown schema before cryptographic work.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;

use crate::Result;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StrictHeader {
    alg: String,
    pub(crate) kid: String,
    typ: String,
}

pub(crate) fn strict_header(token: &str) -> Result<StrictHeader> {
    if token.len() > 32 * 1024 {
        return Err(crate::jwt_verifier::rejected());
    }
    let encoded = token
        .split('.')
        .next()
        .ok_or_else(crate::jwt_verifier::rejected)?;
    if encoded.len() > 2 * 1024 {
        return Err(crate::jwt_verifier::rejected());
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| crate::jwt_verifier::rejected())?;
    let header: StrictHeader =
        serde_json::from_slice(&bytes).map_err(|_| crate::jwt_verifier::rejected())?;
    if header.alg != "RS256"
        || header.typ != "JWT"
        || !crate::validation::opaque_identifier(&header.kid, 128)
    {
        return Err(crate::jwt_verifier::rejected());
    }
    Ok(header)
}
