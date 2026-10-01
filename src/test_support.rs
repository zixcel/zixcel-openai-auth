//! Deterministic ports keep authorization tests offline and reproducible.

use std::{
    collections::VecDeque,
    future::Future,
    sync::{
        Mutex,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
};

use crate::{
    AuthFailureReason, AuthTransport, Clock, HttpMethod, JwtVerification, JwtVerifier,
    RandomSource, Result, TransportFuture, TransportRequest, TransportResponse, VerificationFuture,
    VerifiedClaims,
};

pub(crate) struct TestClock(pub(crate) AtomicU64);
impl TestClock {
    pub(crate) const fn new(value: u64) -> Self {
        Self(AtomicU64::new(value))
    }
    pub(crate) fn set(&self, value: u64) {
        self.0.store(value, Ordering::SeqCst);
    }
}
impl Clock for TestClock {
    fn unix_seconds(&self) -> Result<u64> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

pub(crate) struct TestRandom(AtomicU8);
impl TestRandom {
    pub(crate) const fn new() -> Self {
        Self(AtomicU8::new(1))
    }
}
impl RandomSource for TestRandom {
    fn fill(&self, output: &mut [u8]) -> Result<()> {
        let value = self.0.fetch_add(1, Ordering::SeqCst);
        output.fill(value);
        Ok(())
    }
}

pub(crate) struct CapturedRequest {
    pub(crate) method: HttpMethod,
    pub(crate) url: String,
    pub(crate) body: Vec<u8>,
}

pub(crate) struct MockTransport {
    responses: Mutex<VecDeque<TransportResponse>>,
    requests: Mutex<Vec<CapturedRequest>>,
}
impl MockTransport {
    pub(crate) fn new(responses: Vec<TransportResponse>) -> Self {
        Self {
            responses: Mutex::new(responses.into()),
            requests: Mutex::new(Vec::new()),
        }
    }
    pub(crate) fn take_requests(&self) -> Vec<CapturedRequest> {
        std::mem::take(&mut *self.requests.lock().expect("request lock"))
    }
}
impl AuthTransport for MockTransport {
    fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        let (method, url, _, body) = request.into_parts();
        self.requests
            .lock()
            .expect("request lock")
            .push(CapturedRequest { method, url, body });
        let response = self
            .responses
            .lock()
            .expect("response lock")
            .pop_front()
            .ok_or_else(|| {
                crate::AuthFailure::new(
                    AuthFailureReason::TransportUnavailable,
                    false,
                    "mock exhausted",
                )
            });
        Box::pin(async move { response })
    }
}

pub(crate) struct MockVerifier {
    pub(crate) account_id: &'static str,
    pub(crate) user_id: &'static str,
}
impl JwtVerifier for MockVerifier {
    fn verify<'a>(&'a self, request: JwtVerification<'a>) -> VerificationFuture<'a> {
        let result = VerifiedClaims::after_signature_verification(
            request.issuer().to_owned(),
            request.audience().to_owned(),
            request.now() + 3600,
            request.now().saturating_sub(10),
            None,
            request.nonce().map(str::to_owned),
            Some("user@example.test".to_owned()),
            Some("team".to_owned()),
            Some(self.user_id.to_owned()),
            Some(self.account_id.to_owned()),
            false,
        );
        Box::pin(async move { result })
    }
}

pub(crate) fn response(status: u16, body: impl Into<Vec<u8>>) -> TransportResponse {
    TransportResponse::new(status, body.into()).expect("valid mock response")
}
pub(crate) fn token_body(id: &str, access: &str, refresh: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "id_token": id, "access_token": access, "refresh_token": refresh,
    }))
    .expect("token fixture")
}
pub(crate) fn query(url: &str, key: &str) -> String {
    url::Url::parse(url)
        .expect("test URL")
        .query_pairs()
        .find(|(candidate, _)| candidate == key)
        .expect("query field")
        .1
        .into_owned()
}
pub(crate) fn block_on<T>(future: impl Future<Output = T>) -> T {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}
