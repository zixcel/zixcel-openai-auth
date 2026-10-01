use crate::{
    DevicePollState, OpenAiAuthProfile, request_device_code,
    test_support::{MockTransport, MockVerifier, TestClock, block_on, response, token_body},
};

#[test]
fn device_flow_polls_then_exchanges_verified_code() {
    let profile = OpenAiAuthProfile::codex_managed();
    let clock = TestClock::new(20_000);
    let code_verifier = "C".repeat(43);
    let challenge = crate::encoding::challenge(&code_verifier);
    let transport = MockTransport::new(vec![
        response(
            200,
            br#"{"device_auth_id":"device-a","user_code":"ABCD-EFGH","interval":"5"}"#.to_vec(),
        ),
        response(403, Vec::new()),
        response(
            200,
            serde_json::to_vec(&serde_json::json!({
                "authorization_code": "device-code", "code_challenge": challenge,
                "code_verifier": code_verifier,
            }))
            .expect("code fixture"),
        ),
        response(200, token_body("id-token", "access-token", "refresh-token")),
    ]);
    let mut attempt =
        block_on(request_device_code(&profile, &transport, &clock)).expect("device attempt");
    assert_eq!(
        attempt.verification_url(),
        "https://auth.openai.com/codex/device"
    );
    assert_eq!(attempt.user_code(), "ABCD-EFGH");
    let verifier = MockVerifier {
        account_id: "account-a",
        user_id: "user-a",
    };
    assert!(matches!(
        block_on(attempt.poll(&profile, &transport, &verifier, &clock)).expect("pending"),
        DevicePollState::Pending {
            retry_after_seconds: 5
        }
    ));
    assert!(matches!(
        block_on(attempt.poll(&profile, &transport, &verifier, &clock)).expect("local wait"),
        DevicePollState::Pending {
            retry_after_seconds: 5
        }
    ));
    clock.set(20_005);
    let session = match block_on(attempt.poll(&profile, &transport, &verifier, &clock))
        .expect("authorized")
    {
        DevicePollState::Authorized(session) => session,
        DevicePollState::Pending { .. } => panic!("expected authorization"),
    };
    assert_eq!(session.projection().user_id(), Some("user-a"));
    let requests = transport.take_requests();
    assert_eq!(requests.len(), 4);
    assert!(requests[0].url.ends_with("/deviceauth/usercode"));
    assert!(requests[1].url.ends_with("/deviceauth/token"));
    assert!(requests[3].url.ends_with("/oauth/token"));
}

#[test]
fn invalid_device_pkce_consumes_attempt() {
    let profile = OpenAiAuthProfile::codex_managed();
    let clock = TestClock::new(20_000);
    let transport = MockTransport::new(vec![
        response(200, br#"{"device_auth_id":"device-a","user_code":"ABCD","interval":1}"#.to_vec()),
        response(200, br#"{"authorization_code":"code","code_challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","code_verifier":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}"#.to_vec()),
    ]);
    let mut attempt =
        block_on(request_device_code(&profile, &transport, &clock)).expect("device attempt");
    let verifier = MockVerifier {
        account_id: "account-a",
        user_id: "user-a",
    };
    let error = block_on(attempt.poll(&profile, &transport, &verifier, &clock))
        .err()
        .expect("PKCE rejection");
    assert_eq!(error.reason(), crate::AuthFailureReason::PkceMismatch);
    let error = block_on(attempt.poll(&profile, &transport, &verifier, &clock))
        .err()
        .expect("replay rejection");
    assert_eq!(error.reason(), crate::AuthFailureReason::ReplayDetected);
}
