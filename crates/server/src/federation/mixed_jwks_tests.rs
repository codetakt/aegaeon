use super::*;
use crate::test_utils::jwk_usage::{material, sign, unusable_siblings, KID};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, Header};
use serde_json::json;

#[test]
fn jwk_mixed_federation_statement_and_trust_mark_real_signatures() {
    for algorithm in [Algorithm::RS256, Algorithm::PS256, Algorithm::ES256] {
        let (key, signer) = material(algorithm);
        let claims = json!({"iss":"https://issuer.example","sub":"https://subject.example","iat":100,"exp":1000,"id":"https://mark.example"});
        let token = sign(algorithm, &signer, &claims);
        let mark = TrustMark {
            id: "https://mark.example".into(),
            trust_mark: token.clone(),
        };
        for bad in unusable_siblings(&key) {
            for keys in [
                vec![key.clone(), bad.clone()],
                vec![bad.clone(), key.clone()],
            ] {
                let value = json!({"keys":keys});
                let set = JwkSet::from_verification_value(value.clone()).unwrap();
                assert!(verify_entity_statement(&token, &set).is_ok());
                assert!(verify_trust_mark(&mark, "https://subject.example", &set, 200).is_ok());
                let mut statement = parse_entity_statement_unverified(&token).unwrap();
                statement.jwks = Some(value.clone());
                assert_eq!(statement.parse_jwks().unwrap(), set);
                let stored = StoredTrustAnchor {
                    id: uuid::Uuid::new_v4(),
                    environment_id: uuid::Uuid::new_v4(),
                    entity_id: "https://issuer.example".into(),
                    jwks: value,
                    metadata_policy: None,
                    created_at: 100,
                    updated_at: 100,
                };
                assert_eq!(stored.to_trust_anchor().unwrap().jwks, set);
            }
        }
        let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
        let mut signature = URL_SAFE_NO_PAD.decode(&parts[2]).unwrap();
        signature[0] ^= 1;
        parts[2] = URL_SAFE_NO_PAD.encode(signature);
        let set = JwkSet::from_value(json!({"keys":[key]})).unwrap();
        assert!(verify_entity_statement(&parts.join("."), &set).is_err());
        assert!(verify_trust_mark(
            &TrustMark {
                id: mark.id.clone(),
                trust_mark: parts.join(".")
            },
            "https://subject.example",
            &set,
            200
        )
        .is_err());
        let no_kid = jsonwebtoken::encode(&Header::new(algorithm), &claims, &signer).unwrap();
        assert!(verify_entity_statement(&no_kid, &set).is_ok());
        let (mut other, _) = material(if algorithm == Algorithm::ES256 {
            Algorithm::RS256
        } else {
            Algorithm::ES256
        });
        other["kid"] = json!("other");
        let ambiguous = JwkSet::from_value(json!({"keys":[key,other]})).unwrap();
        assert!(verify_entity_statement(&no_kid, &ambiguous).is_err());
        assert!(verify_trust_mark(
            &TrustMark {
                id: mark.id.clone(),
                trust_mark: no_kid
            },
            "https://subject.example",
            &ambiguous,
            200
        )
        .is_err());
        let duplicate =
            JwkSet::from_verification_value(json!({"keys":[key,{"kty":"OKP","kid":KID}]})).unwrap();
        assert!(verify_entity_statement(&token, &duplicate).is_err());
        assert!(verify_trust_mark(&mark, "https://subject.example", &duplicate, 200).is_err());
    }
}
