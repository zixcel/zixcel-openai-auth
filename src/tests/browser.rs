use crate::{
    AuthFailureReason, BrowserAttempt, BrowserCallback, HttpMethod, OpenAiAuthProfile,
    test_support::{
        MockTransport, MockVerifier, TestClock, TestRandom, block_on, query, response, token_body,
    },
};

#[test]
fn browser_flow_binds_state_nonce_and_workspace() {
    let profile = OpenAiAuthProfile::codex_managed()
        .restrict_workspaces(vec!["workspace-a".to_owned()])
        .expect("profile");
    let clock = TestClock::new(10_000);
    let mut attempt =
        BrowserAttempt::begin(&profile, 1455, &TestRandom::new(), &clock).expect("browser attempt");
    let url = attempt.authorization_plan().url().to_owned();
    assert_eq!(profile.callback_ports(), &[1455]);
    assert_eq!(query(&url, "client_id"), profile.client_id());
    assert_eq!(
        query(&url, "redirect_uri"),
        "http://localhost:1455/auth/callback"
    );
    assert_eq!(query(&url, "allowed_workspace_id"), "workspace-a");
    assert_eq!(query(&url, "originator"), "codex_cli_rs");
    let callback = BrowserCallback::new("authorization-code".to_owned(), query(&url, "state"))
        .expect("callback");
    let transport = MockTransport::new(vec![response(
        200,
        token_body("id-token", "access-token", "refresh-token"),
    )]);
    let session = block_on(attempt.complete(
        callback,
        &profile,
        &transport,
        &MockVerifier {
            account_id: "workspace-a",
            user_id: "user-a",
        },
        &clock,
    ))
    .expect("session");
    assert_eq!(session.projection().account_id(), Some("workspace-a"));
    let requests = transport.take_requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, HttpMethod::Post);
    assert!(requests[0].url.ends_with("/oauth/token"));
}

#[test]
fn wrong_state_does_not_consume_attempt() {
    let profile = OpenAiAuthProfile::codex_managed();
    let clock = TestClock::new(10_000);
    let mut attempt =
        BrowserAttempt::begin(&profile, 1455, &TestRandom::new(), &clock).expect("browser attempt");
    let correct_state = query(attempt.authorization_plan().url(), "state");
    let transport = MockTransport::new(vec![response(
        200,
        token_body("id-token", "access-token", "refresh-token"),
    )]);
    let verifier = MockVerifier {
        account_id: "workspace-a",
        user_id: "user-a",
    };
    let callback = BrowserCallback::new("code".to_owned(), "A".repeat(43)).expect("callback");
    let error = block_on(attempt.complete(callback, &profile, &transport, &verifier, &clock))
        .err()
        .expect("state mismatch");
    assert_eq!(error.reason(), AuthFailureReason::StateMismatch);
    let callback = BrowserCallback::new("code".to_owned(), correct_state).expect("callback");
    let session = block_on(attempt.complete(callback, &profile, &transport, &verifier, &clock))
        .expect("correct callback remains usable");
    assert_eq!(session.projection().user_id(), Some("user-a"));
    let callback = BrowserCallback::new("code".to_owned(), "B".repeat(43)).expect("callback");
    let error = block_on(attempt.complete(callback, &profile, &transport, &verifier, &clock))
        .err()
        .expect("replay");
    assert_eq!(error.reason(), AuthFailureReason::ReplayDetected);
}

#[test]
fn provider_body_is_never_in_failure() {
    let profile = OpenAiAuthProfile::codex_managed();
    let clock = TestClock::new(10_000);
    let mut attempt =
        BrowserAttempt::begin(&profile, 1455, &TestRandom::new(), &clock).expect("browser attempt");
    let state = query(attempt.authorization_plan().url(), "state");
    let transport = MockTransport::new(vec![response(400, b"secret-provider-detail".to_vec())]);
    let error = block_on(attempt.complete(
        BrowserCallback::new("code".to_owned(), state).expect("callback"),
        &profile,
        &transport,
        &MockVerifier {
            account_id: "a",
            user_id: "u",
        },
        &clock,
    ))
    .err()
    .expect("denied");
    assert!(!format!("{error:?} {error}").contains("secret-provider-detail"));
}

#[test]
fn workspace_policy_rejects_other_accounts() {
    let profile = OpenAiAuthProfile::codex_managed()
        .restrict_workspaces(vec!["approved".to_owned()])
        .expect("profile");
    let clock = TestClock::new(10_000);
    let mut attempt =
        BrowserAttempt::begin(&profile, 1455, &TestRandom::new(), &clock).expect("browser attempt");
    let state = query(attempt.authorization_plan().url(), "state");
    let transport = MockTransport::new(vec![response(
        200,
        token_body("id-token", "access-token", "refresh-token"),
    )]);
    let error = block_on(attempt.complete(
        BrowserCallback::new("code".to_owned(), state).expect("callback"),
        &profile,
        &transport,
        &MockVerifier {
            account_id: "other",
            user_id: "user-a",
        },
        &clock,
    ))
    .err()
    .expect("workspace rejection");
    assert_eq!(error.reason(), AuthFailureReason::WorkspaceRejected);
}
