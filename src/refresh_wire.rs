//! Refresh responses retain only credential fields and zeroize them after use.

use serde::Deserialize;
use zeroize::Zeroize;

use crate::{AuthFailureReason, Result, error::failure, validation::secret};

#[allow(clippy::struct_field_names)]
#[derive(Deserialize)]
pub(crate) struct RefreshWire {
    pub(crate) id_token: Option<String>,
    pub(crate) access_token: Option<String>,
    pub(crate) refresh_token: Option<String>,
}

impl RefreshWire {
    pub(crate) fn parse(body: &[u8]) -> Result<Self> {
        let wire: Self = serde_json::from_slice(body).map_err(|_| invalid())?;
        if wire.id_token.is_none() && wire.access_token.is_none() && wire.refresh_token.is_none() {
            return Err(invalid());
        }
        for value in [
            wire.id_token.as_deref(),
            wire.access_token.as_deref(),
            wire.refresh_token.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            secret(value)?;
        }
        Ok(wire)
    }
}

impl Drop for RefreshWire {
    fn drop(&mut self) {
        for value in [
            &mut self.id_token,
            &mut self.access_token,
            &mut self.refresh_token,
        ]
        .into_iter()
        .flatten()
        {
            value.zeroize();
        }
    }
}

pub(crate) fn invalid() -> crate::AuthFailure {
    failure(
        AuthFailureReason::InvalidResponse,
        false,
        "OpenAI refresh response was rejected",
    )
}
