//! Injected ports keep network, time, entropy, and key acquisition outside the core.

use std::{future::Future, pin::Pin};

use zeroize::Zeroize;

use crate::{AuthFailureReason, Result, error::failure};

pub type TransportFuture<'a> = Pin<Box<dyn Future<Output = Result<TransportResponse>> + Send + 'a>>;

pub trait AuthTransport: Send + Sync {
    fn send(&self, request: TransportRequest) -> TransportFuture<'_>;
}

pub trait Clock: Send + Sync {
    /// Returns the trusted Unix time.
    ///
    /// # Errors
    /// Returns a canonical failure when trusted time is unavailable.
    fn unix_seconds(&self) -> Result<u64>;
}

pub trait RandomSource: Send + Sync {
    /// Fills the complete output with cryptographically secure random bytes.
    ///
    /// # Errors
    /// Returns a canonical failure when sufficient entropy is unavailable.
    fn fill(&self, output: &mut [u8]) -> Result<()>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    Get,
    Post,
}

pub struct TransportRequest {
    method: HttpMethod,
    url: String,
    content_type: Option<&'static str>,
    body: Vec<u8>,
}

impl TransportRequest {
    pub(crate) fn get(url: String) -> Self {
        Self {
            method: HttpMethod::Get,
            url,
            content_type: None,
            body: Vec::new(),
        }
    }

    pub(crate) fn post(url: String, content_type: &'static str, body: Vec<u8>) -> Self {
        Self {
            method: HttpMethod::Post,
            url,
            content_type: Some(content_type),
            body,
        }
    }

    #[must_use]
    pub const fn method(&self) -> HttpMethod {
        self.method
    }

    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    #[must_use]
    pub const fn content_type(&self) -> Option<&'static str> {
        self.content_type
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    #[must_use]
    pub fn into_parts(mut self) -> (HttpMethod, String, Option<&'static str>, Vec<u8>) {
        (
            self.method,
            std::mem::take(&mut self.url),
            self.content_type,
            std::mem::take(&mut self.body),
        )
    }
}

impl Drop for TransportRequest {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

pub struct TransportResponse {
    status: u16,
    body: Vec<u8>,
}

impl TransportResponse {
    /// Wraps a status and already-bounded response body.
    ///
    /// # Errors
    /// Zeroizes and rejects invalid statuses or bodies larger than 64 KiB.
    pub fn new(status: u16, mut body: Vec<u8>) -> Result<Self> {
        if !(100..=599).contains(&status) || body.len() > 64 * 1024 {
            body.zeroize();
            return Err(failure(
                AuthFailureReason::ResponseTooLarge,
                false,
                "provider response was rejected",
            ));
        }
        Ok(Self { status, body })
    }

    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }
}

impl Drop for TransportResponse {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}
