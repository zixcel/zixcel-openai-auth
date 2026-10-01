//! The production profile is immutable and matches the supported Codex managed flow.

use std::collections::BTreeSet;

use crate::{AuthFailureReason, Result, error::failure, validation::opaque_identifier};

const ISSUER: &str = "https://auth.openai.com";
const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
// Keep this redirect URI byte-for-byte aligned with the registered Codex CLI
// browser flow. OpenAI validates OAuth redirect URIs as exact values.
const CALLBACK_PORTS: [u16; 1] = [1455];
const SCOPES: &str =
    "openid profile email offline_access api.connectors.read api.connectors.invoke";

pub struct OpenAiAuthProfile {
    allowed_workspaces: BTreeSet<String>,
}

#[allow(clippy::unused_self)]
impl OpenAiAuthProfile {
    #[must_use]
    pub fn codex_managed() -> Self {
        Self {
            allowed_workspaces: BTreeSet::new(),
        }
    }

    /// Restricts accepted account claims to a closed workspace set.
    ///
    /// # Errors
    /// Returns a canonical failure for an empty, duplicate, or malformed set.
    pub fn restrict_workspaces(mut self, values: Vec<String>) -> Result<Self> {
        if values.is_empty() || values.len() > 16 {
            return Err(invalid_profile());
        }
        for value in values {
            if !opaque_identifier(&value, 128) || !self.allowed_workspaces.insert(value) {
                return Err(invalid_profile());
            }
        }
        Ok(self)
    }

    #[must_use]
    pub const fn issuer(&self) -> &'static str {
        ISSUER
    }

    #[must_use]
    pub const fn client_id(&self) -> &'static str {
        CLIENT_ID
    }

    #[must_use]
    pub const fn callback_ports(&self) -> &'static [u16] {
        &CALLBACK_PORTS
    }

    #[must_use]
    pub const fn scopes(&self) -> &'static str {
        SCOPES
    }

    pub(crate) const fn originator(&self) -> &'static str {
        "codex_cli_rs"
    }

    /// Builds a callback URI only for a registered managed port.
    ///
    /// # Errors
    /// Returns a canonical failure when the port is outside the fixed allow-list.
    pub fn callback_uri(&self, port: u16) -> Result<String> {
        if !CALLBACK_PORTS.contains(&port) {
            return Err(invalid_profile());
        }
        Ok(format!("http://localhost:{port}/auth/callback"))
    }

    pub(crate) fn workspace_allowed(&self, actual: Option<&str>) -> bool {
        self.allowed_workspaces.is_empty()
            || actual.is_some_and(|value| self.allowed_workspaces.contains(value))
    }

    pub(crate) fn workspace_query_value(&self) -> Option<String> {
        (!self.allowed_workspaces.is_empty()).then(|| {
            self.allowed_workspaces
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(",")
        })
    }

    pub(crate) fn authorize_endpoint(&self) -> String {
        format!("{ISSUER}/oauth/authorize")
    }

    pub(crate) fn token_endpoint(&self) -> String {
        format!("{ISSUER}/oauth/token")
    }

    pub(crate) fn revoke_endpoint(&self) -> String {
        format!("{ISSUER}/oauth/revoke")
    }

    pub(crate) fn device_endpoint(&self, operation: &str) -> String {
        format!("{ISSUER}/api/accounts/deviceauth/{operation}")
    }

    pub(crate) fn device_verification_url(&self) -> String {
        format!("{ISSUER}/codex/device")
    }

    pub(crate) fn device_callback_uri(&self) -> String {
        format!("{ISSUER}/deviceauth/callback")
    }

    pub(crate) fn jwks_endpoint(&self) -> String {
        format!("{ISSUER}/.well-known/jwks.json")
    }
}

fn invalid_profile() -> crate::AuthFailure {
    failure(
        AuthFailureReason::InvalidProfile,
        false,
        "OpenAI authorization profile is invalid",
    )
}
