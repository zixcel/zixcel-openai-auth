//! Closed validation helpers are shared without exporting permissive parsers.

use crate::{AuthFailureReason, Result, error::failure};

pub(crate) fn bounded_text(value: &str, maximum: usize, field: &'static str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= maximum
        && value
            .chars()
            .all(|character| !character.is_control() && character != '\0');
    valid
        .then_some(())
        .ok_or_else(|| failure(AuthFailureReason::InvalidResponse, false, field))
}

pub(crate) fn opaque_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub(crate) fn base64url(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub(crate) fn secret(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 32 * 1024 || value.chars().any(char::is_control) {
        return Err(failure(
            AuthFailureReason::InvalidResponse,
            false,
            "provider returned invalid credential material",
        ));
    }
    Ok(())
}
