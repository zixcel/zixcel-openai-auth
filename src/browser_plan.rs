//! The displayable browser plan contains the reviewed authorization URL only.

use crate::{AuthFailureReason, OpenAiAuthProfile, Result, error::failure};

pub struct BrowserAuthorizationPlan<'a> {
    url: &'a str,
    callback_port: u16,
}

impl<'a> BrowserAuthorizationPlan<'a> {
    pub(crate) const fn new(url: &'a str, callback_port: u16) -> Self {
        Self { url, callback_port }
    }

    #[must_use]
    pub const fn url(&self) -> &str {
        self.url
    }

    #[must_use]
    pub const fn callback_port(&self) -> u16 {
        self.callback_port
    }
}

pub(crate) fn authorization_url(
    profile: &OpenAiAuthProfile,
    callback_uri: &str,
    state: &str,
    nonce: &str,
    challenge: &str,
) -> Result<String> {
    let mut url = url::Url::parse(&profile.authorize_endpoint()).map_err(|_| invalid_plan())?;
    let mut query = url.query_pairs_mut();
    for (key, value) in [
        ("response_type", "code"),
        ("client_id", profile.client_id()),
        ("redirect_uri", callback_uri),
        ("scope", profile.scopes()),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        ("id_token_add_organizations", "true"),
        ("codex_cli_simplified_flow", "true"),
        ("state", state),
        ("nonce", nonce),
        ("originator", profile.originator()),
    ] {
        query.append_pair(key, value);
    }
    if let Some(value) = profile.workspace_query_value() {
        query.append_pair("allowed_workspace_id", &value);
    }
    drop(query);
    Ok(url.into())
}

pub(crate) fn invalid_plan() -> crate::AuthFailure {
    failure(
        AuthFailureReason::InvalidPlan,
        false,
        "browser authorization plan is invalid",
    )
}
