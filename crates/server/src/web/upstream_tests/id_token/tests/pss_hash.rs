use super::*;
use crate::web::upstream_id_token::{
    validate_upstream_id_token, verify_upstream_id_token_claims, UpstreamIdTokenValidationInput,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use sha2::{Digest, Sha256, Sha384, Sha512};

const ACCESS: &str = "sample-access-token";
const CODE: &str = "authorization-code-123";

struct SignedFixture {
    alg: Algorithm,
    name: &'static str,
    key: EncodingKey,
    jwks: JwkSet,
    discovery: OidcDiscovery,
}

impl SignedFixture {
    fn new(alg: Algorithm) -> Result<Self, String> {
        let name = jwt_alg_name(alg).ok_or("algorithm")?;
        let (key, jwks) = if alg == Algorithm::ES256 {
            use ring::signature::KeyPair as _;
            let pem_bytes = include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/p256-private.pk8.pem"
            ));
            let der = pem::parse(pem_bytes).map_err(|e| e.to_string())?;
            let pair = ring::signature::EcdsaKeyPair::from_pkcs8(
                &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                der.contents(),
                &ring::rand::SystemRandom::new(),
            )
            .map_err(|e| e.to_string())?;
            let point = pair.public_key().as_ref();
            let jwks = JwkSet::from_value(json!({"keys":[{"kty":"EC", "crv":"P-256", "alg":"ES256", "kid":"upstream-kid", "use":"sig", "x":URL_SAFE_NO_PAD.encode(&point[1..33]), "y":URL_SAFE_NO_PAD.encode(&point[33..65])}]})).map_err(|e| e.to_string())?;
            (
                EncodingKey::from_ec_pem(pem_bytes).map_err(|e| e.to_string())?,
                jwks,
            )
        } else {
            let rsa = upstream_signing_key()?;
            (
                EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes())
                    .map_err(|e| e.to_string())?,
                upstream_jwks_with_alg(&rsa, name)?,
            )
        };
        let mut discovery = base_discovery(TEST_ISSUER)?;
        discovery.id_token_signing_alg_values_supported = vec![name.to_string()];
        Ok(Self {
            alg,
            name,
            key,
            jwks,
            discovery,
        })
    }

    fn expected_hash(&self, source: &str) -> String {
        match self.alg {
            Algorithm::PS384 => URL_SAFE_NO_PAD.encode(&Sha384::digest(source)[..24]),
            Algorithm::PS512 => URL_SAFE_NO_PAD.encode(&Sha512::digest(source)[..32]),
            _ => URL_SAFE_NO_PAD.encode(&Sha256::digest(source)[..16]),
        }
    }

    fn sign(&self, payload: &serde_json::Value) -> Result<String, String> {
        let mut header = Header::new(self.alg);
        header.kid = Some("upstream-kid".to_string());
        jsonwebtoken::encode(&header, payload, &self.key).map_err(|e| e.to_string())
    }

    fn verified(&self, token: &str) -> Result<IdToken, String> {
        let (claims, alg) = verify_upstream_id_token_claims(
            token,
            &self.jwks,
            &self.discovery,
            aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN,
        )
        .map_err(|e| format!("real signature verification: {e:?}"))?;
        assert_eq!(alg, self.name);
        Ok(IdToken {
            claims,
            signing_alg: alg.to_string(),
        })
    }
}

fn validate_hash_claims(
    token: &IdToken,
    access: Option<&str>,
    code: Option<&str>,
) -> Result<(), String> {
    validate_upstream_id_token(
        token,
        &UpstreamIdTokenValidationInput {
            client_id: "client",
            issuer: TEST_ISSUER,
            expected_nonce: Some("nonce"),
            max_age: None,
            access_token: access,
            code,
            requested_acr: None,
            jwt_leeway_secs: 60,
        },
    )
}

fn signed_hash_scenario(alg: Algorithm) -> TestResult {
    let _guard = crate::util::RAW_JSON_ENV_GUARD
        .lock()
        .map_err(|_| "raw json env guard")?;
    let _header_backend = use_jose_header_verified_structural_backend();
    let _payload_backend = use_oidc_id_token_payload_verified_structural_backend();
    let fixture = SignedFixture::new(alg)?;
    let now = now_epoch_secs()?;
    let payload = json!({"iss":TEST_ISSUER, "sub":"subject", "aud":"client", "iat":now, "exp":now+3600, "nonce":"nonce", "at_hash":fixture.expected_hash(ACCESS), "c_hash":fixture.expected_hash(CODE)});
    let signed = fixture.sign(&payload)?;
    let verified = fixture.verified(&signed)?;
    validate_hash_claims(&verified, Some(ACCESS), Some(CODE))?;
    assert_eq!(verified.signing_alg, fixture.name);
    assert!(validate_hash_claims(&verified, None, Some(CODE))
        .unwrap_err()
        .contains("access_token missing"));
    assert!(validate_hash_claims(&verified, Some(ACCESS), None)
        .unwrap_err()
        .contains("authorization code missing"));
    for field in ["at_hash", "c_hash"] {
        let mut changed = payload.clone();
        changed[field] = json!("tampered-hash");
        let token = fixture.verified(&fixture.sign(&changed)?)?;
        let error = require_err(
            validate_hash_claims(&token, Some(ACCESS), Some(CODE)),
            "tampered hash accepted",
        )?;
        assert!(error.contains(&format!("{field} mismatch")), "{error}");
    }
    let mut optional = payload;
    let object = optional.as_object_mut().ok_or("payload object")?;
    object.remove("at_hash");
    object.remove("c_hash");
    let token = fixture.verified(&fixture.sign(&optional)?)?;
    validate_hash_claims(&token, Some(ACCESS), Some(CODE))?;
    validate_hash_claims(&token, None, None)?;
    let (prefix, sig) = signed.rsplit_once('.').ok_or("signature")?;
    let mut bytes = URL_SAFE_NO_PAD.decode(sig).map_err(|e| e.to_string())?;
    bytes[0] ^= 1;
    let tampered = format!("{prefix}.{}", URL_SAFE_NO_PAD.encode(bytes));
    assert!(
        fixture.verified(&tampered).is_err(),
        "matching hashes cannot rescue a bad signature"
    );
    Ok(())
}

#[test]
fn oidc_pss_hash_upstream_ps256_signed_hash_claims() -> TestResult {
    signed_hash_scenario(Algorithm::PS256)
}
#[test]
fn oidc_pss_hash_upstream_ps384_signed_hash_claims() -> TestResult {
    signed_hash_scenario(Algorithm::PS384)
}
#[test]
fn oidc_pss_hash_upstream_ps512_signed_hash_claims() -> TestResult {
    signed_hash_scenario(Algorithm::PS512)
}
#[test]
fn oidc_pss_hash_upstream_rs256_signed_hash_control() -> TestResult {
    signed_hash_scenario(Algorithm::RS256)
}
#[test]
fn oidc_pss_hash_upstream_es256_signed_hash_control() -> TestResult {
    signed_hash_scenario(Algorithm::ES256)
}
