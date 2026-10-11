//! Shared TLS issuer and cryptographic checks for the resource consumers.
use super::{
    authorization_fixture_reply, fixture_reply, fixture_token, rsa_fixture_key, FixtureReply,
};
use crate::{accounting::HttpAccounting, LoadTestResults};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

pub(super) const SENSITIVE_MARKER: &str = "response-private-value-195";
pub(super) const RS_NONCE: &str = "resource-nonce";

#[derive(Clone, Debug)]
pub(super) struct VerifiedProof {
    pub(super) jwk: Value,
    pub(super) claims: Value,
}

pub(super) type ProofTranscript = Arc<Mutex<Vec<VerifiedProof>>>;

pub(super) fn header<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    let (headers, _) = request.split_once("\r\n\r\n").unwrap();
    let mut values = headers.lines().filter_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name).then(|| value.trim())
    });
    let first = values.next();
    assert!(values.next().is_none(), "duplicate {name} header");
    first
}

fn verified_proof(request: &str, base: &str, method: &str, endpoint: &str) -> VerifiedProof {
    let proof = header(request, "DPoP").unwrap();
    let parts: Vec<_> = proof.split('.').collect();
    assert_eq!(parts.len(), 3);
    let jose: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(jose["alg"], "EdDSA");
    assert_eq!(jose["typ"], "dpop+jwt");
    let jwk = jose["jwk"].clone();
    assert_eq!(jwk["kty"], "OKP");
    assert_eq!(jwk["crv"], "Ed25519");
    assert!(jwk.get("d").is_none());
    let key_bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(jwk["x"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).unwrap();
    let signature =
        ed25519_dalek::Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
    key.verify_strict(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .unwrap();
    assert_eq!(claims["htm"], method);
    assert_eq!(claims["htu"], format!("{base}{endpoint}"));
    assert!(claims["iat"].as_u64().is_some());
    assert_eq!(
        uuid::Uuid::parse_str(claims["jti"].as_str().unwrap())
            .unwrap()
            .get_version_num(),
        4
    );
    VerifiedProof { jwk, claims }
}

pub(super) fn record_userinfo_proof(
    transcript: &ProofTranscript,
    request: &str,
    base: &str,
    nonce: Option<&str>,
) {
    assert!(request.starts_with("GET /userinfo "));
    assert_eq!(header(request, "Authorization"), Some("DPoP token"));
    assert!(header(request, "Cookie").is_none());
    let proof = verified_proof(request, base, "GET", "/userinfo");
    assert_eq!(
        proof.claims["ath"],
        URL_SAFE_NO_PAD.encode(Sha256::digest(b"token"))
    );
    assert_eq!(proof.claims.get("nonce").and_then(Value::as_str), nonce);
    let mut proofs = transcript.lock().unwrap();
    assert_eq!(proof.jwk, proofs[0].jwk);
    assert!(proofs
        .iter()
        .all(|prior| prior.claims["jti"] != proof.claims["jti"]));
    proofs.push(proof);
}

pub(super) fn resource_challenge() -> FixtureReply {
    let mut reply = fixture_reply(401, br#"{"error":"use_dpop_nonce"}"#.to_vec());
    reply.headers = vec![
        (
            "WWW-Authenticate".into(),
            "DPoP error=\"use_dpop_nonce\"".into(),
        ),
        ("DPoP-Nonce".into(), RS_NONCE.into()),
    ];
    reply
}

pub(super) struct OidcIssuer {
    key: jsonwebtoken::EncodingKey,
    pub(super) jwks: Vec<u8>,
    pub(super) subject: &'static str,
    nonce: Option<String>,
    pub(super) proofs: ProofTranscript,
}

impl OidcIssuer {
    pub(super) fn new() -> Self {
        let (key, jwks) = rsa_fixture_key();
        Self {
            key,
            jwks,
            subject: "subject",
            nonce: None,
            proofs: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub(super) fn setup_reply(
        &mut self,
        step: usize,
        request: &str,
        base: &str,
    ) -> Option<FixtureReply> {
        match step {
            0 => {
                let (reply, nonce) = authorization_fixture_reply(request, base);
                assert!(nonce.is_some());
                self.nonce = nonce;
                Some(reply)
            }
            1 => {
                assert!(request.starts_with("POST /token "));
                assert!(header(request, "Authorization")
                    .unwrap()
                    .starts_with("Basic "));
                assert!(header(request, "Cookie").is_none());
                let proof = verified_proof(request, base, "POST", "/token");
                assert!(proof.claims.get("ath").is_none());
                assert!(proof.claims.get("nonce").is_none());
                self.proofs.lock().unwrap().push(proof);
                Some(self.token_reply(base))
            }
            2 => {
                assert!(request.starts_with("GET /.well-known/jwks.json "));
                assert!(header(request, "Authorization").is_none());
                assert!(header(request, "Cookie").is_none());
                Some(fixture_reply(200, self.jwks.clone()))
            }
            _ => None,
        }
    }

    fn token_reply(&self, base: &str) -> FixtureReply {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let hash = |value: &[u8]| URL_SAFE_NO_PAD.encode(&Sha256::digest(value)[..16]);
        let claims = serde_json::json!({
            "iss": base, "sub": self.subject, "aud": "client+ id",
            "nonce": self.nonce.as_ref().unwrap(), "iat": now, "exp": now + 300,
            "at_hash": hash(b"token"), "c_hash": hash(b"code")
        });
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some("signing".into());
        let mut token = fixture_token(true, 300);
        token["id_token"] = jsonwebtoken::encode(&header, &claims, &self.key)
            .unwrap()
            .into();
        fixture_reply(200, serde_json::to_vec(&token).unwrap())
    }
}

pub(super) fn assert_http(
    accounting: &HttpAccounting,
    methods: &[(&str, u64)],
    statuses: &[(&str, u64)],
) {
    accounting.validate().unwrap();
    let attempts: u64 = methods.iter().map(|(_, count)| count).sum();
    assert_eq!(accounting.attempts, attempts);
    assert_eq!(accounting.responses, attempts);
    assert_eq!(accounting.transport_failures, 0);
    assert_eq!(accounting.body_failures, 0);
    let map = |entries: &[(&str, u64)]| -> BTreeMap<String, u64> {
        entries
            .iter()
            .map(|(key, count)| ((*key).to_owned(), *count))
            .collect()
    };
    assert_eq!(accounting.methods_endpoints, map(methods));
    assert_eq!(accounting.statuses, map(statuses));
}

pub(super) async fn assert_report_redaction(
    error: &anyhow::Error,
    leg: &str,
    accounting: HttpAccounting,
) {
    for text in [
        format!("{error}"),
        format!("{error:#}"),
        format!("{error:?}"),
    ] {
        assert!(!text.contains(SENSITIVE_MARKER));
    }
    assert!(error
        .chain()
        .all(|source| !source.to_string().contains(SENSITIVE_MARKER)));
    accounting.validate().unwrap();
    let mut report = LoadTestResults::try_new().unwrap();
    report.main_phase.http = accounting;
    report
        .main_phase
        .legs
        .entry(leg.into())
        .or_default()
        .record(false, leg == "introspection-missing-client-auth");
    let category = format!("{leg}: {error}");
    report
        .record_request(1, false, Some(category.clone()))
        .await;
    assert_eq!(report.total_requests, 1);
    assert_eq!(report.failed_requests, 1);
    assert_eq!(report.successful_requests, 0);
    assert_eq!(report.error_categories.len(), 1);
    assert_eq!(report.error_categories[&category], 1);
    assert!(report.main_phase.legs[leg].valid());
    assert_eq!(report.main_phase.legs[leg].failures, 1);
    assert!(report.main_phase.validate(&[leg.into()]).is_err());
    let serialized = serde_json::to_string(&report).unwrap();
    assert!(!serialized.contains(SENSITIVE_MARKER));
    let decoded: Value = serde_json::from_str(&serialized).unwrap();
    assert_eq!(decoded["error_categories"][category.as_str()], 1);
}
