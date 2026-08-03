use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use jsonwebtoken::{encode, EncodingKey, Header};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct PkcePair {
    pub verifier: String,
    pub challenge: String,
}

/// Test data generator for load testing
pub struct TestDataGenerator {
    rng: StdRng,
    dpop_signing_key: SigningKey,
}

impl TestDataGenerator {
    #[must_use]
    pub fn new() -> Self {
        let mut rng = StdRng::from_entropy();
        let mut key_bytes = [0u8; 32];
        rng.fill_bytes(&mut key_bytes);
        Self {
            rng,
            dpop_signing_key: SigningKey::from_bytes(&key_bytes),
        }
    }

    /// Generate a random client ID
    pub fn client_id(&mut self) -> String {
        format!("client_{}", uuid::Uuid::new_v4())
    }

    /// Generate a random client secret
    pub fn client_secret(&mut self) -> String {
        let bytes: Vec<u8> = (0..32).map(|_| self.rng.gen()).collect();
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Generate a random state parameter
    pub fn state(&mut self) -> String {
        let bytes: Vec<u8> = (0..16).map(|_| self.rng.gen()).collect();
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Generate a random nonce
    pub fn nonce(&mut self) -> String {
        let bytes: Vec<u8> = (0..16).map(|_| self.rng.gen()).collect();
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Generate PKCE verifier
    pub fn pkce_verifier(&mut self) -> String {
        self.pkce_pair().verifier
    }

    /// Generate PKCE challenge from verifier
    pub fn pkce_challenge(&mut self) -> String {
        self.pkce_pair().challenge
    }

    /// Generate PKCE verifier/challenge pair
    pub fn pkce_pair(&mut self) -> PkcePair {
        use sha2::{Digest, Sha256};

        let bytes: Vec<u8> = (0..32).map(|_| self.rng.gen()).collect();
        let verifier = URL_SAFE_NO_PAD.encode(bytes);
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());

        PkcePair {
            verifier,
            challenge,
        }
    }

    /// Generate a mock authorization code
    pub fn authorization_code(&mut self) -> String {
        let bytes: Vec<u8> = (0..24).map(|_| self.rng.gen()).collect();
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Generate a mock access token
    pub fn access_token(&mut self) -> String {
        let bytes: Vec<u8> = (0..32).map(|_| self.rng.gen()).collect();
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Generate a mock refresh token
    pub fn refresh_token(&mut self) -> String {
        let bytes: Vec<u8> = (0..32).map(|_| self.rng.gen()).collect();
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Generate a request URI for PAR
    pub fn request_uri(&mut self) -> String {
        format!("urn:ietf:params:oauth:request_uri:{}", uuid::Uuid::new_v4())
    }

    fn dpop_ath(access_token: &str) -> String {
        use sha2::{Digest, Sha256};

        let digest = Sha256::digest(access_token.as_bytes());
        URL_SAFE_NO_PAD.encode(digest)
    }

    /// Generate a `DPoP` proof `JWT`.
    pub fn dpop_proof(
        &mut self,
        htm: &str,
        htu: &str,
        nonce: Option<&str>,
        access_token: Option<&str>,
    ) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());

        let verifying_key = self.dpop_signing_key.verifying_key();

        let mut header_map = Map::new();
        header_map.insert("alg".to_string(), Value::String("EdDSA".to_string()));
        header_map.insert("typ".to_string(), Value::String("dpop+jwt".to_string()));

        let mut jwk_map = Map::new();
        jwk_map.insert("kty".to_string(), Value::String("OKP".to_string()));
        jwk_map.insert("crv".to_string(), Value::String("Ed25519".to_string()));
        jwk_map.insert(
            "x".to_string(),
            Value::String(URL_SAFE_NO_PAD.encode(verifying_key.as_bytes())),
        );
        header_map.insert("jwk".to_string(), Value::Object(jwk_map));

        let mut payload_map = Map::new();
        payload_map.insert("htm".to_string(), Value::String(htm.to_string()));
        payload_map.insert("htu".to_string(), Value::String(htu.to_string()));
        payload_map.insert("iat".to_string(), Value::Number(now.into()));
        payload_map.insert(
            "jti".to_string(),
            Value::String(uuid::Uuid::new_v4().to_string()),
        );
        if let Some(token) = access_token {
            payload_map.insert("ath".to_string(), Value::String(Self::dpop_ath(token)));
        }
        if let Some(value) = nonce {
            payload_map.insert("nonce".to_string(), Value::String(value.to_string()));
        }

        let Ok(header_json) = serde_json::to_string(&Value::Object(header_map)) else {
            return "invalid_dpop".to_string();
        };
        let Ok(payload_json) = serde_json::to_string(&Value::Object(payload_map)) else {
            return "invalid_dpop".to_string();
        };

        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = self.dpop_signing_key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("{signing_input}.{sig_b64}")
    }

    /// Generate a mock `JWT` token.
    pub fn jwt_token(&mut self) -> String {
        #[derive(Debug, Serialize, Deserialize)]
        struct Claims {
            sub: String,
            aud: String,
            exp: u64,
            iat: u64,
            jti: String,
            scope: String,
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());

        let claims = Claims {
            sub: format!("user_{}", self.rng.gen::<u32>()),
            aud: "https://api.example.com".to_string(),
            exp: now + 3600,
            iat: now,
            jti: uuid::Uuid::new_v4().to_string(),
            scope: "read write".to_string(),
        };

        let key = EncodingKey::from_secret(b"test_secret");

        encode(&Header::default(), &claims, &key).unwrap_or_else(|_| "invalid_jwt".to_string())
    }

    /// Generate random user agent
    pub fn user_agent(&mut self) -> String {
        let agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        ];
        agents[self.rng.gen_range(0..agents.len())].to_string()
    }

    /// Generate random IP address
    pub fn ip_address(&mut self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.rng.gen_range(1..255),
            self.rng.gen_range(0..255),
            self.rng.gen_range(0..255),
            self.rng.gen_range(1..255)
        )
    }
}

impl Default for TestDataGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_payload(proof: &str) -> Value {
        let payload = proof.split('.').nth(1).expect("dpop proof payload segment");
        let decoded = URL_SAFE_NO_PAD
            .decode(payload)
            .expect("base64url payload decoding");
        serde_json::from_slice(&decoded).expect("JSON payload decoding")
    }

    #[test]
    fn dpop_proof_omits_nonce_when_not_requested() {
        let mut generator = TestDataGenerator::new();
        let proof = generator.dpop_proof("POST", "http://127.0.0.1:8080/token", None, None);
        let payload = decode_payload(&proof);

        assert_eq!(payload["htm"], "POST");
        assert_eq!(payload["htu"], "http://127.0.0.1:8080/token");
        assert!(payload.get("nonce").is_none());
        assert!(payload.get("ath").is_none());
    }

    #[test]
    fn dpop_proof_embeds_nonce_when_requested() {
        let mut generator = TestDataGenerator::new();
        let proof = generator.dpop_proof(
            "POST",
            "http://127.0.0.1:8080/token",
            Some("server-issued-nonce"),
            None,
        );
        let payload = decode_payload(&proof);

        assert_eq!(payload["nonce"], "server-issued-nonce");
    }

    #[test]
    fn dpop_proof_embeds_ath_when_access_token_is_present() {
        let mut generator = TestDataGenerator::new();
        let proof = generator.dpop_proof(
            "GET",
            "http://127.0.0.1:8080/userinfo",
            None,
            Some("access-token-value"),
        );
        let payload = decode_payload(&proof);

        assert_eq!(
            payload["ath"],
            TestDataGenerator::dpop_ath("access-token-value")
        );
    }
}
