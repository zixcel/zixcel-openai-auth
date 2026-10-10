#![doc = include_str!("../README.crate.md")]
//! Zixcel-owned `OpenAI` account authorization plans with explicit security ports.

mod account;
mod browser;
mod browser_callback;
mod browser_plan;
mod claims;
mod custody;
mod device;
mod device_plan;
mod device_request;
mod device_wire;
mod encoding;
mod error;
mod jwks;
mod jwt_header;
mod jwt_verifier;
mod ports;
mod profile;
mod provider;
mod refresh;
mod refresh_material;
mod refresh_wire;
mod revoke;
mod session;
mod session_restore;
mod token_exchange;
mod validation;

pub use account::AccountProjection;
pub use browser::BrowserAttempt;
pub use browser_callback::BrowserCallback;
pub use browser_plan::BrowserAuthorizationPlan;
pub use claims::{JwtVerification, JwtVerifier, VerificationFuture, VerifiedClaims};
pub use custody::CustodyParts;
pub use device::{DeviceAttempt, DevicePollState};
pub use device_plan::{DeviceCodeRequestPlan, DevicePollPlan};
pub use device_request::request_device_code;
pub use error::{AuthFailure, AuthFailureReason, Result};
pub use jwks::{JwksRequestPlan, fetch_openai_jwt_verifier};
pub use jwt_verifier::OpenAiJwtVerifier;
pub use ports::{
    AuthTransport, Clock, HttpMethod, RandomSource, TransportFuture, TransportRequest,
    TransportResponse,
};
pub use profile::OpenAiAuthProfile;
pub use refresh::{RefreshPlan, refresh_session};
pub use refresh_material::{RefreshMaterial, refresh_stored_session, restore_refresh_material};
pub use revoke::{RevocationMaterial, RevokePlan, revoke_refresh_token, revoke_session};
pub use session::SessionMaterial;
pub use session_restore::restore_session;
pub use token_exchange::TokenExchangePlan;

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;
