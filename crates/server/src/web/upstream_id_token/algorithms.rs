pub(in crate::web) fn jwt_alg_name(alg: jsonwebtoken::Algorithm) -> Option<&'static str> {
    match alg {
        jsonwebtoken::Algorithm::RS256 => Some("RS256"),
        jsonwebtoken::Algorithm::RS384 => Some("RS384"),
        jsonwebtoken::Algorithm::RS512 => Some("RS512"),
        jsonwebtoken::Algorithm::PS256 => Some("PS256"),
        jsonwebtoken::Algorithm::PS384 => Some("PS384"),
        jsonwebtoken::Algorithm::PS512 => Some("PS512"),
        jsonwebtoken::Algorithm::ES256 => Some("ES256"),
        jsonwebtoken::Algorithm::ES384 => Some("ES384"),
        _ => None,
    }
}

pub(super) fn jwt_alg_requires_rsa(alg: jsonwebtoken::Algorithm) -> bool {
    matches!(
        alg,
        jsonwebtoken::Algorithm::RS256
            | jsonwebtoken::Algorithm::RS384
            | jsonwebtoken::Algorithm::RS512
            | jsonwebtoken::Algorithm::PS256
            | jsonwebtoken::Algorithm::PS384
            | jsonwebtoken::Algorithm::PS512
    )
}

pub(super) fn jwt_alg_curve(alg: jsonwebtoken::Algorithm) -> Option<&'static str> {
    match alg {
        jsonwebtoken::Algorithm::ES256 => Some("P-256"),
        jsonwebtoken::Algorithm::ES384 => Some("P-384"),
        _ => None,
    }
}
