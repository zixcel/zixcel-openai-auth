use crate::{
    AuthFailureReason, JwtVerification, JwtVerifier, OpenAiAuthProfile, RevocationMaterial,
    SessionMaterial, VerificationFuture, VerifiedClaims, refresh_session, refresh_stored_session,
    restore_refresh_material, revoke_refresh_token,
    test_support::{MockTransport, MockVerifier, TestClock, block_on, response},
};

fn session(account: &str, access: &str, refresh: &str) -> SessionMaterial {
    SessionMaterial::create(
        "old-id".to_owned(),
        access.to_owned(),
        refresh.to_owned(),
        VerifiedClaims::after_signature_verification(
            "https://auth.openai.com".to_owned(),
            "app_EMoamEEZ73f0CkXaXp7hrann".to_owned(),
            13_600,
            9_990,
            None,
            None,
            Some("old@example.test".to_owned()),
            Some("team".to_owned()),
            Some("user-a".to_owned()),
            Some(account.to_owned()),
            false,
        )
        .expect("claims"),
    )
    .expect("session")
}

struct ExpiredVerifier;
impl JwtVerifier for ExpiredVerifier {
    fn verify<'a>(&'a self, request: JwtVerification<'a>) -> VerificationFuture<'a> {
        let claims = VerifiedClaims::after_signature_verification(
            request.issuer().to_owned(),
            request.audience().to_owned(),
            request.now() - 1,
            request.now() - 3600,
            None,
            None,
            Some("old@example.test".to_owned()),
            Some("team".to_owned()),
            Some("user-a".to_owned()),
            Some("account-a".to_owned()),
            false,
        );
        Box::pin(async move { claims })
    }
}

#[test]
fn refresh_rejects_identity_switch_without_partial_commit() {
    let profile = OpenAiAuthProfile::codex_managed();
    let clock = TestClock::new(10_000);
    let mut active = session("account-a", "old-access", "old-refresh");
    let transport = MockTransport::new(vec![response(
        200,
        br#"{"id_token":"new-id","access_token":"new-access","refresh_token":"new-refresh"}"#
            .to_vec(),
    )]);
    let error = block_on(refresh_session(
        &mut active,
        &profile,
        &transport,
        &MockVerifier {
            account_id: "account-b",
            user_id: "user-a",
        },
        &clock,
    ))
    .expect_err("identity switch");
    assert_eq!(error.reason(), AuthFailureReason::ClaimsBindingMismatch);
    let (id, access, refresh, projection) = active.into_custody_parts().expose_for_custody();
    assert_eq!(
        (id.as_str(), access.as_str(), refresh.as_str()),
        ("old-id", "old-access", "old-refresh")
    );
    assert_eq!(projection.account_id(), Some("account-a"));
}

#[test]
fn refresh_maps_closed_provider_reason() {
    let profile = OpenAiAuthProfile::codex_managed();
    let clock = TestClock::new(10_000);
    let mut active = session("account-a", "old-access", "old-refresh");
    let transport = MockTransport::new(vec![response(
        401,
        br#"{"error":{"code":"refresh_token_reused","message":"secret"}}"#.to_vec(),
    )]);
    let error = block_on(refresh_session(
        &mut active,
        &profile,
        &transport,
        &MockVerifier {
            account_id: "account-a",
            user_id: "user-a",
        },
        &clock,
    ))
    .expect_err("reused");
    assert_eq!(error.reason(), AuthFailureReason::RefreshTokenReused);
    assert!(!format!("{error:?}").contains("secret"));
}

#[test]
fn revocation_material_does_not_require_active_id_token() {
    let profile = OpenAiAuthProfile::codex_managed();
    let material = RevocationMaterial::new("refresh-only".to_owned()).expect("material");
    let transport = MockTransport::new(vec![response(200, Vec::new())]);
    block_on(revoke_refresh_token(&material, &profile, &transport)).expect("revoked");
    let requests = transport.take_requests();
    assert_eq!(requests.len(), 1);
    assert!(String::from_utf8_lossy(&requests[0].body).contains("refresh-only"));
}

#[test]
fn expired_signed_identity_can_rotate_into_active_session() {
    let profile = OpenAiAuthProfile::codex_managed();
    let clock = TestClock::new(10_000);
    let material = block_on(restore_refresh_material(
        "expired-signed-id".to_owned(),
        "valid-refresh".to_owned(),
        &profile,
        &ExpiredVerifier,
        &clock,
    ))
    .expect("refresh anchor");
    let transport = MockTransport::new(vec![response(
        200,
        br#"{"id_token":"new-id","access_token":"new-access","refresh_token":"new-refresh"}"#
            .to_vec(),
    )]);
    let session = block_on(refresh_stored_session(
        material,
        &profile,
        &transport,
        &MockVerifier {
            account_id: "account-a",
            user_id: "user-a",
        },
        &clock,
    ))
    .expect("active session");
    assert_eq!(session.access_token_for_request(), "new-access");
    assert_eq!(session.projection().account_id(), Some("account-a"));
}
