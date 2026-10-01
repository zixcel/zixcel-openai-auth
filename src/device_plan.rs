//! Device endpoint requests are explicit, secret-bearing transport plans.

use serde::Serialize;

use crate::{OpenAiAuthProfile, Result, TransportRequest};

pub struct DeviceCodeRequestPlan {
    request: TransportRequest,
}

impl DeviceCodeRequestPlan {
    /// Creates the fixed managed-device request.
    ///
    /// # Errors
    /// Returns a canonical failure if the request cannot be represented safely.
    pub fn for_profile(profile: &OpenAiAuthProfile) -> Result<Self> {
        let body = serde_json::to_vec(&ClientRequest {
            client_id: profile.client_id(),
        })
        .map_err(|_| crate::device_wire::invalid())?;
        Ok(Self {
            request: TransportRequest::post(
                profile.device_endpoint("usercode"),
                "application/json",
                body,
            ),
        })
    }

    #[must_use]
    pub fn into_request(self) -> TransportRequest {
        self.request
    }
}

pub struct DevicePollPlan {
    request: TransportRequest,
}

impl DevicePollPlan {
    pub(crate) fn new(
        profile: &OpenAiAuthProfile,
        device_auth_id: &str,
        user_code: &str,
    ) -> Result<Self> {
        let body = serde_json::to_vec(&PollRequest {
            device_auth_id,
            user_code,
        })
        .map_err(|_| crate::device_wire::invalid())?;
        Ok(Self {
            request: TransportRequest::post(
                profile.device_endpoint("token"),
                "application/json",
                body,
            ),
        })
    }

    #[must_use]
    pub fn into_request(self) -> TransportRequest {
        self.request
    }
}

#[derive(Serialize)]
struct ClientRequest<'a> {
    client_id: &'a str,
}

#[derive(Serialize)]
struct PollRequest<'a> {
    device_auth_id: &'a str,
    user_code: &'a str,
}
