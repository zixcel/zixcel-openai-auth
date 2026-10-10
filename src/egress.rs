//! Managed provider admission is pure validation, independent of network effects.
use crate::{AuthFailureReason, HttpMethod, Result, TransportRequest, error::failure};
use url::Url;

const AUTH_HOST: &str = "auth.openai.com";

/// Closed route policy for the managed `OpenAI` account authorization protocol.
/// Callers must apply the response limit while reading and disable redirects.
pub struct OpenAiAuthorizationEgress;

impl OpenAiAuthorizationEgress {
    /// Maximum admitted authorization request or response body size.
    pub const RESPONSE_BYTE_LIMIT: usize = 64 * 1024;

    /// Validates a request before the caller performs an external network effect.
    /// Rejected requests retain their automatic sensitive-body cleanup.
    ///
    /// # Errors
    /// Rejects unsupported origins, routes, content types or oversized bodies.
    pub fn authorize(request: TransportRequest) -> Result<TransportRequest> {
        let parsed = Url::parse(request.url()).map_err(|_| rejected())?;
        let valid = parsed.scheme() == "https"
            && parsed.host_str() == Some(AUTH_HOST)
            && parsed.port().is_none_or(|port| port == 443)
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.query().is_none()
            && parsed.fragment().is_none()
            && route_is_allowed(request.method(), parsed.path(), request.content_type());
        if !valid || request.body().len() > Self::RESPONSE_BYTE_LIMIT {
            return Err(rejected());
        }
        Ok(request)
    }
}

fn rejected() -> crate::AuthFailure {
    failure(
        AuthFailureReason::InvalidPlan,
        false,
        "authorization egress was rejected",
    )
}

fn route_is_allowed(method: HttpMethod, path: &str, content_type: Option<&str>) -> bool {
    matches!(
        (method, path, content_type),
        (HttpMethod::Get, "/.well-known/jwks.json", None)
            | (
                HttpMethod::Post,
                "/oauth/token",
                Some("application/json" | "application/x-www-form-urlencoded")
            )
            | (
                HttpMethod::Post,
                "/oauth/revoke"
                    | "/api/accounts/deviceauth/usercode"
                    | "/api/accounts/deviceauth/token",
                Some("application/json")
            )
    )
}

#[cfg(test)]
#[path = "egress/tests.rs"]
mod tests;
