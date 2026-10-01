//! Device attempts are created only after a bounded provider response is accepted.

use crate::{
    AuthTransport, Clock, DeviceAttempt, DeviceCodeRequestPlan, OpenAiAuthProfile, Result,
    provider, validation,
};

/// Requests a short-lived device authorization ceremony.
///
/// # Errors
/// Returns a canonical failure for invalid transport, time, status, or payload data.
pub async fn request_device_code(
    profile: &OpenAiAuthProfile,
    transport: &impl AuthTransport,
    clock: &impl Clock,
) -> Result<DeviceAttempt> {
    let response = transport
        .send(DeviceCodeRequestPlan::for_profile(profile)?.into_request())
        .await?;
    provider::accepted(&response, provider::Operation::Authorize)?;
    let mut wire: crate::device_wire::DeviceWire =
        serde_json::from_slice(response.body()).map_err(|_| crate::device_wire::invalid())?;
    validation::bounded_text(
        &wire.device_auth_id,
        256,
        "device authorization id is invalid",
    )?;
    validation::bounded_text(&wire.user_code, 64, "device user code is invalid")?;
    let interval = wire.interval.parse()?;
    let now = clock.unix_seconds()?;
    Ok(DeviceAttempt::new(
        profile.device_verification_url(),
        std::mem::take(&mut wire.user_code),
        std::mem::take(&mut wire.device_auth_id),
        interval,
        now,
    ))
}
