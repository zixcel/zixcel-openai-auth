use crate::{
    AuthFailureReason, JwtVerification, JwtVerifier, OpenAiAuthProfile, SessionMaterial,
    VerificationFuture, VerifiedClaims, refresh_session,
    test_support::{MockTransport, TestClock, block_on, response},
};

fn claims(user: Option<&str>, account: Option<&str>) -> VerifiedClaims {
    VerifiedClaims::after_signature_verification(
        "https://auth.openai.com".to_owned(),
        "app_EMoamEEZ73f0CkXaXp7hrann".to_owned(),
        13_600,
        9_990,
        None,
        None,
        None,
        Some("team".to_owned()),
        user.map(str::to_owned),
        account.map(str::to_owned),
        false,
    )
    .expect("claims fixture")
}

struct MissingIdentityVerifier;
impl JwtVerifier for MissingIdentityVerifier {
    fn verify<'a>(&'a self, request: JwtVerification<'a>) -> VerificationFuture<'a> {
        let result = VerifiedClaims::after_signature_verification(
            request.issuer().to_owned(),
            request.audience().to_owned(),
            request.now() + 3600,
            request.now() - 10,
            None,
            request.nonce().map(str::to_owned),
            None,
            Some("team".to_owned()),
            None,
            None,
            false,
        );
        Box::pin(async move { result })
    }
}

#[test]
fn managed_session_requires_a_stable_identifier() {
    let error = SessionMaterial::create(
        "id".to_owned(),
        "access".to_owned(),
        "refresh".to_owned(),
        claims(None, None),
    )
    .err()
    .expect("missing identity rejection");
    assert_eq!(error.reason(), AuthFailureReason::ClaimsBindingMismatch);
}

#[test]
fn refresh_rejects_identifier_downgrade_without_mutation() {
    let mut session = SessionMaterial::create(
        "old-id".to_owned(),
        "old-access".to_owned(),
        "old-refresh".to_owned(),
        claims(Some("user-a"), Some("account-a")),
    )
    .expect("active session");
    let transport = MockTransport::new(vec![response(
        200,
        br#"{"id_token":"new-id","access_token":"new-access","refresh_token":"new-refresh"}"#
            .to_vec(),
    )]);
    let profile = OpenAiAuthProfile::codex_managed();
    let error = block_on(refresh_session(
        &mut session,
        &profile,
        &transport,
        &MissingIdentityVerifier,
        &TestClock::new(10_000),
    ))
    .expect_err("identity downgrade");
    assert_eq!(error.reason(), AuthFailureReason::ClaimsBindingMismatch);
    let (id, access, refresh, _) = session.into_custody_parts().expose_for_custody();
    assert_eq!(
        (id.as_str(), access.as_str(), refresh.as_str()),
        ("old-id", "old-access", "old-refresh")
    );
}
