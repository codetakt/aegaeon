use super::algorithms::jwt_alg_name;
use super::errors::UpstreamIdTokenSignatureError;
use crate::upstream::canonical_base64url_segment;
use crate::{oidc::OidcDiscovery, util};
use aegaeon_jose::jwk::JwkSet;
#[cfg(test)]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

pub(in crate::web) struct AdmittedUpstreamIdTokenHeader {
    pub(super) header: jsonwebtoken::Header,
    pub(super) alg_name: &'static str,
}

impl AdmittedUpstreamIdTokenHeader {
    pub(in crate::web) fn unfamiliar_kid(&self, jwks: &JwkSet) -> bool {
        self.header.kid.as_deref().is_some_and(|kid| {
            !kid.is_empty()
                && !jwks
                    .keys()
                    .iter()
                    .any(|key| key.kid.as_deref() == Some(kid))
        })
    }
}

pub(in crate::web) fn admit_upstream_id_token_header(
    token: &str,
    discovery: &OidcDiscovery,
    jose_header_max_len: usize,
) -> Result<AdmittedUpstreamIdTokenHeader, UpstreamIdTokenSignatureError> {
    if token.len() > super::super::UPSTREAM_MAX_BODY_BYTES {
        return Err(UpstreamIdTokenSignatureError::HeaderInvalid);
    }
    let header = util::decode_compact_jwt_header_without_duplicate_keys_with_max_len(
        token,
        jose_header_max_len,
    )
    .map_err(|err| match err {
        util::JsonObjectParseError::BackendPolicy => UpstreamIdTokenSignatureError::Internal(
            "unsupported raw JSON backend for jose-header".to_string(),
        ),
        util::JsonObjectParseError::DuplicateKey
        | util::JsonObjectParseError::InvalidJson
        | util::JsonObjectParseError::TrailingBytes
        | util::JsonObjectParseError::InvalidShape => UpstreamIdTokenSignatureError::HeaderInvalid,
    })?;
    let alg = header.alg;
    let alg_name = jwt_alg_name(alg).ok_or(UpstreamIdTokenSignatureError::AlgNotAllowed)?;
    if !discovery
        .id_token_signing_alg_values_supported
        .iter()
        .any(|value| value == alg_name)
    {
        return Err(UpstreamIdTokenSignatureError::AlgNotSupported);
    }

    admit_compact_body(token)?;
    Ok(AdmittedUpstreamIdTokenHeader { header, alg_name })
}

fn admit_compact_body(token: &str) -> Result<(), UpstreamIdTokenSignatureError> {
    let mut parts = token.split('.');
    let (Some(_), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(UpstreamIdTokenSignatureError::HeaderInvalid);
    };
    if !canonical_base64url_segment(payload) {
        return Err(UpstreamIdTokenSignatureError::PayloadInvalid);
    }
    if !canonical_base64url_segment(signature) {
        return Err(UpstreamIdTokenSignatureError::SignatureInvalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_metadata_algorithm_identifiers_require_exact_matching() {
        use jsonwebtoken::Algorithm::{ES256, ES384, PS256, PS384, PS512, RS256, RS384, RS512};
        let mut discovery = crate::web::upstream_tests::base_discovery("https://issuer.example")
            .expect("discovery");
        for algorithm in [RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384] {
            let name = jwt_alg_name(algorithm).expect("supported algorithm");
            let header = URL_SAFE_NO_PAD
                .encode(serde_json::json!({"alg":name,"kid":"unfamiliar"}).to_string());
            let token = format!("{header}.e30.c2ln");
            for variant in [
                name.to_ascii_lowercase(),
                format!(" {name}"),
                format!("{name} "),
                format!("{name}\t"),
            ] {
                discovery.id_token_signing_alg_values_supported = vec![variant.clone()];
                assert!(
                    matches!(
                        admit_upstream_id_token_header(&token, &discovery, 4096),
                        Err(UpstreamIdTokenSignatureError::AlgNotSupported)
                    ),
                    "nonexact algorithm accepted: {variant:?}"
                );
            }
            discovery.id_token_signing_alg_values_supported = vec![name.into()];
            assert!(admit_upstream_id_token_header(&token, &discovery, 4096).is_ok());
            discovery
                .id_token_signing_alg_values_supported
                .insert(0, name.to_ascii_lowercase());
            assert!(admit_upstream_id_token_header(&token, &discovery, 4096).is_ok());
        }
    }

    #[test]
    fn upstream_jwks_refresh_compact_segment_chunks_match_strict_base64() {
        for len in [1, 2, 3, 767, 768, 769, 1537, 8192] {
            let encoded = URL_SAFE_NO_PAD.encode(vec![0x55; len]);
            assert!(canonical_base64url_segment(&encoded));
            for suffix in ["=", "+", "/", "!", "a", "YR"] {
                let variant = format!("{encoded}{suffix}");
                assert_eq!(
                    canonical_base64url_segment(&variant),
                    URL_SAFE_NO_PAD.decode(&variant).is_ok()
                );
            }
        }
        for invalid in ["", "a", "YR", "e31", "YQ=="] {
            assert!(!canonical_base64url_segment(invalid));
        }
    }

    #[test]
    fn upstream_jwks_refresh_compact_total_size_is_bounded_before_decode() {
        let discovery = crate::web::upstream_tests::base_discovery("https://issuer.example")
            .expect("discovery");
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","kid":"unknown"}"#);
        let token = format!(
            "{header}.{}.c2ln",
            "A".repeat(super::super::super::UPSTREAM_MAX_BODY_BYTES)
        );
        assert!(matches!(
            admit_upstream_id_token_header(&token, &discovery, 4096),
            Err(UpstreamIdTokenSignatureError::HeaderInvalid)
        ));
    }
}
