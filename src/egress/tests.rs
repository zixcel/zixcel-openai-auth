//! Admission tests use no live accounts, credentials or network calls.
use super::*;

#[test]
fn accepts_managed_routes_and_preserves_request_parts() {
    let request = TransportRequest::get("https://auth.openai.com/.well-known/jwks.json".into());
    let admitted = OpenAiAuthorizationEgress::authorize(request).expect("managed JWKS");
    assert_eq!(admitted.method(), HttpMethod::Get);
    for (path, content_type) in [
        ("/oauth/token", "application/json"),
        ("/oauth/token", "application/x-www-form-urlencoded"),
        ("/oauth/revoke", "application/json"),
        ("/api/accounts/deviceauth/usercode", "application/json"),
        ("/api/accounts/deviceauth/token", "application/json"),
    ] {
        let url = format!("https://auth.openai.com{path}");
        let request = TransportRequest::post(url.clone(), content_type, b"{}".to_vec());
        let (_, actual, actual_type, body) = OpenAiAuthorizationEgress::authorize(request)
            .expect("managed request")
            .into_parts();
        assert_eq!(actual, url);
        assert_eq!(actual_type, Some(content_type));
        assert_eq!(body, b"{}");
    }
}

#[test]
fn rejects_route_origin_and_content_type_confusion() {
    for url in [
        "http://auth.openai.com/oauth/token",
        "https://example.com/oauth/token",
        "https://auth.openai.com:444/oauth/token",
        "https://user@auth.openai.com/oauth/token",
        "https://user:dummy@auth.openai.com/oauth/token",
        "https://auth.openai.com/oauth/token#fragment",
        "https://auth.openai.com/oauth/token?alternate=true",
        "https://auth.openai.com/unlisted",
    ] {
        let request = TransportRequest::post(url.into(), "application/json", Vec::new());
        assert_eq!(
            OpenAiAuthorizationEgress::authorize(request)
                .err()
                .expect("rejected")
                .reason(),
            AuthFailureReason::InvalidPlan
        );
    }
    assert!(
        OpenAiAuthorizationEgress::authorize(TransportRequest::get(
            "https://auth.openai.com/oauth/token".into()
        ))
        .is_err()
    );
    assert!(
        OpenAiAuthorizationEgress::authorize(TransportRequest::post(
            "https://auth.openai.com/oauth/revoke".into(),
            "application/x-www-form-urlencoded",
            Vec::new()
        ))
        .is_err()
    );
}

#[test]
fn accepts_the_body_boundary_and_rejects_growth() {
    let limit = OpenAiAuthorizationEgress::RESPONSE_BYTE_LIMIT;
    for (size, accepted) in [(limit, true), (limit + 1, false)] {
        let request = TransportRequest::post(
            "https://auth.openai.com/oauth/token".into(),
            "application/json",
            vec![0; size],
        );
        assert_eq!(
            OpenAiAuthorizationEgress::authorize(request).is_ok(),
            accepted
        );
    }
    assert!(crate::TransportResponse::new(200, vec![0; limit]).is_ok());
    assert!(crate::TransportResponse::new(200, vec![0; limit + 1]).is_err());
}
