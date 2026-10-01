//! Provider device payloads are bounded and zeroized before leaving the parser.

use serde::Deserialize;
use zeroize::Zeroize;

use crate::{AuthFailureReason, Result, error::failure};

#[derive(Deserialize)]
pub(crate) struct DeviceWire {
    pub(crate) device_auth_id: String,
    #[serde(alias = "usercode")]
    pub(crate) user_code: String,
    pub(crate) interval: Interval,
}

#[derive(Deserialize)]
pub(crate) struct CodeWire {
    pub(crate) authorization_code: String,
    pub(crate) code_challenge: String,
    pub(crate) code_verifier: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub(crate) enum Interval {
    Number(u64),
    Text(String),
}

impl Interval {
    pub(crate) fn parse(&self) -> Result<u64> {
        let value = match self {
            Self::Number(value) => *value,
            Self::Text(value) => value.parse().map_err(|_| invalid())?,
        };
        (1..=60)
            .contains(&value)
            .then_some(value)
            .ok_or_else(invalid)
    }
}

pub(crate) fn invalid() -> crate::AuthFailure {
    failure(
        AuthFailureReason::InvalidResponse,
        false,
        "device authorization response was rejected",
    )
}

impl Drop for DeviceWire {
    fn drop(&mut self) {
        self.device_auth_id.zeroize();
        self.user_code.zeroize();
        if let Interval::Text(value) = &mut self.interval {
            value.zeroize();
        }
    }
}

impl Drop for CodeWire {
    fn drop(&mut self) {
        self.authorization_code.zeroize();
        self.code_challenge.zeroize();
        self.code_verifier.zeroize();
    }
}
