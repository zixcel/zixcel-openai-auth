//! Encoding helpers create bounded protocol values without owning transport policy.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{RandomSource, Result};

pub(crate) fn random_secret(random: &impl RandomSource) -> Result<String> {
    let mut bytes = [0_u8; 32];
    random.fill(&mut bytes)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub(crate) fn pkce(random: &impl RandomSource) -> Result<(String, String)> {
    let verifier = random_secret(random)?;
    let challenge = challenge(&verifier);
    Ok((verifier, challenge))
}

pub(crate) fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

pub(crate) fn form(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in fields {
        serializer.append_pair(key, value);
    }
    serializer.finish().into_bytes()
}

pub(crate) fn equal_secret(left: &str, right: &str) -> bool {
    let left = Sha256::digest(left.as_bytes());
    let right = Sha256::digest(right.as_bytes());
    bool::from(left.ct_eq(&right))
}
