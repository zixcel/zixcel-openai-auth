use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::{
    AuthFailureReason, JwtVerification, JwtVerifier, OpenAiAuthProfile, fetch_openai_jwt_verifier,
    test_support::{MockTransport, block_on, response},
};

const MODULUS: &str = "yRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5_CYYi_cvI-SXVT9kPWSKXxJXBXd_4LkvcPuUakBoAkfh-eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG_AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi-yUod-j8MtvIj812dkS4QMiRVN_by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQ";
const SIGNED_TOKEN: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJodHRwczovL2F1dGgub3BlbmFpLmNvbSIsImF1ZCI6ImFwcF9FTW9hbUVFWjczZjBDa1hhWHA3aHJhbm4iLCJleHAiOjEzNjAwLCJpYXQiOjk5OTAsIm5vbmNlIjoibm9uY2UtYSIsImVtYWlsIjoic2lnbmVkQGV4YW1wbGUudGVzdCIsImh0dHBzOi8vYXBpLm9wZW5haS5jb20vYXV0aCI6eyJjaGF0Z3B0X3BsYW5fdHlwZSI6InRlYW0iLCJjaGF0Z3B0X3VzZXJfaWQiOiJ1c2VyLWEiLCJjaGF0Z3B0X2FjY291bnRfaWQiOiJhY2NvdW50LWEifX0.KjUHfst8APhVeeI9RHQoGYbKnF_DXqhFPa5lKZPmdptB3g6qK77jWjxOAmCzajlPBaigpyQTjBKhNF2PBd0V2m6AnUxNzFTZaEpr5XUzjWNs0LfVH4r2AilMMZ43xKq0XJVhKzVv3ziOjRVdk7gFzHgWmyA8p2Lmxte9pPX4izk7Q4aqT2BWk-7pgRTHRd0pTsxitA2NPeuv2U8p2n-gUFxIvjUVWsktDt4oVV_WanEPjIIxUMuJea1eLzOBmTpOuC8cEepwG27bfxrjSXhiol-W_xo5DnvFtlEnJ2NM_QEshqC1pBcvnzeM_8hfbB6M7f3DwoqZMaAou_297NU_fw";

fn jwks() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"keys":[{
        "kty":"RSA", "n":MODULUS, "e":"AQAB", "kid":"test-key",
        "alg":"RS256", "use":"sig", "key_ops":["verify"]
    }]}))
    .expect("JWKS fixture")
}

fn untrusted_header_token() -> String {
    let mut parts = SIGNED_TOKEN.split('.');
    let _ = parts.next();
    let payload = parts.next().expect("payload");
    let signature = parts.next().expect("signature");
    let header = URL_SAFE_NO_PAD.encode(
        br#"{"typ":"JWT","alg":"RS256","kid":"test-key","jku":"https://attacker.invalid"}"#,
    );
    format!("{header}.{payload}.{signature}")
}

#[test]
fn concrete_verifier_checks_signature_and_bound_claims() {
    let profile = OpenAiAuthProfile::codex_managed();
    let transport = MockTransport::new(vec![response(200, jwks())]);
    let verifier = block_on(fetch_openai_jwt_verifier(&profile, &transport)).expect("verifier");
    let claims = block_on(verifier.verify(JwtVerification::new(
        SIGNED_TOKEN,
        profile.issuer(),
        profile.client_id(),
        Some("nonce-a"),
        10_000,
    )))
    .expect("verified claims");
    assert_eq!(claims.account_id.as_deref(), Some("account-a"));
    let error = block_on(verifier.verify(JwtVerification::new(
        SIGNED_TOKEN,
        profile.issuer(),
        profile.client_id(),
        Some("nonce-b"),
        10_000,
    )))
    .err()
    .expect("nonce rejection");
    assert_eq!(error.reason(), AuthFailureReason::TokenVerificationRejected);
}

#[test]
fn verifier_rejects_unreviewed_header_fields() {
    let profile = OpenAiAuthProfile::codex_managed();
    let transport = MockTransport::new(vec![response(200, jwks())]);
    let verifier = block_on(fetch_openai_jwt_verifier(&profile, &transport)).expect("verifier");
    let token = untrusted_header_token();
    let error = block_on(verifier.verify(JwtVerification::new(
        &token,
        profile.issuer(),
        profile.client_id(),
        Some("nonce-a"),
        10_000,
    )))
    .err()
    .expect("header rejection");
    assert_eq!(error.reason(), AuthFailureReason::TokenVerificationRejected);
}

#[test]
fn jwks_rejects_duplicate_key_ids() {
    let profile = OpenAiAuthProfile::codex_managed();
    let key: serde_json::Value = serde_json::from_slice(&jwks()).expect("fixture");
    let duplicate = serde_json::to_vec(&serde_json::json!({
        "keys":[key["keys"][0].clone(), key["keys"][0].clone()]
    }))
    .expect("duplicate fixture");
    let transport = MockTransport::new(vec![response(200, duplicate)]);
    let error = block_on(fetch_openai_jwt_verifier(&profile, &transport))
        .err()
        .expect("duplicate rejection");
    assert_eq!(error.reason(), AuthFailureReason::TokenVerificationRejected);
}
